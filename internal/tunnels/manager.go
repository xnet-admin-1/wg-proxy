package tunnels

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TunnelStatus represents the current state of a tunnel.
type TunnelStatus int

const (
	StatusStopped TunnelStatus = iota
	StatusStarting
	StatusRunning
	StatusUnhealthy
	StatusError
	StatusDisconnected
)

func (s TunnelStatus) String() string {
	switch s {
	case StatusStopped:
		return "stopped"
	case StatusStarting:
		return "starting"
	case StatusRunning:
		return "healthy"
	case StatusUnhealthy:
		return "unhealthy"
	case StatusError:
		return "error"
	case StatusDisconnected:
		return "disconnected"
	default:
		return "unknown"
	}
}

// Tunnel represents a single wireproxy tunnel instance.
type Tunnel struct {
	Name       string
	ConfigPath string
	ProxyPort  int
	Status     TunnelStatus
	Latency    time.Duration
	LastCheck  time.Time
	StartedAt  time.Time
	Error      string
	Country    string
	ExitIP     string
	BytesIn    atomic.Int64
	BytesOut   atomic.Int64
	ConnCount  atomic.Int64

	mu      sync.RWMutex
	cmd     *exec.Cmd
	tmpConf string
	done    chan struct{}
}

// Lock exposes the mutex for the health checker.
func (t *Tunnel) Lock()    { t.mu.Lock() }
func (t *Tunnel) Unlock()  { t.mu.Unlock() }
func (t *Tunnel) RLock()   { t.mu.RLock() }
func (t *Tunnel) RUnlock() { t.mu.RUnlock() }

// IsHealthy returns true if the tunnel is in a usable state.
func (t *Tunnel) IsHealthy() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Status == StatusRunning
}

// Manager manages multiple wireproxy tunnel instances.
type Manager struct {
	mu        sync.RWMutex
	tunnels   []*Tunnel
	configDir string
	basePort  int
	nextPort  int
}

// NewManager creates a new tunnel manager.
func NewManager(configDir string, basePort int) *Manager {
	return &Manager{
		configDir: configDir,
		basePort:  basePort,
		nextPort:  basePort,
		tunnels:   make([]*Tunnel, 0),
	}
}

// LoadConfigs reads all .conf files from the configuration directory.
func (m *Manager) LoadConfigs() error {
	entries, err := os.ReadDir(m.configDir)
	if err != nil {
		return fmt.Errorf("reading config dir %s: %w", m.configDir, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".conf")
		confPath := filepath.Join(m.configDir, entry.Name())
		tunnel := &Tunnel{
			Name:       name,
			ConfigPath: confPath,
			ProxyPort:  m.nextPort,
			Status:     StatusStopped,
			Country:    extractCountryFromName(name),
		}
		m.tunnels = append(m.tunnels, tunnel)
		m.nextPort++
		log.Printf("[tunnels] Loaded config: %s -> port %d", name, tunnel.ProxyPort)
	}

	log.Printf("[tunnels] Loaded %d tunnel configs", len(m.tunnels))
	return nil
}

// StartAll starts all loaded tunnels.
func (m *Manager) StartAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tunnels {
		go m.startTunnel(t)
	}
}

// StopAll stops all running tunnels.
func (m *Manager) StopAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tunnels {
		m.stopTunnel(t)
	}
	log.Println("[tunnels] All tunnels stopped")
}

// Restart restarts a specific tunnel by name.
func (m *Manager) Restart(name string) error {
	t := m.GetTunnel(name)
	if t == nil {
		return fmt.Errorf("tunnel %q not found", name)
	}
	m.stopTunnel(t)
	go m.startTunnel(t)
	return nil
}

// GetTunnel returns a tunnel by name.
func (m *Manager) GetTunnel(name string) *Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tunnels {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// GetTunnels returns all tunnels.
func (m *Manager) GetTunnels() []*Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Tunnel, len(m.tunnels))
	copy(result, m.tunnels)
	return result
}

// HealthyBackends returns ports of all healthy tunnels.
func (m *Manager) HealthyBackends() []int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var ports []int
	for _, t := range m.tunnels {
		if t.IsHealthy() {
			ports = append(ports, t.ProxyPort)
		}
	}
	return ports
}

func (m *Manager) startTunnel(t *Tunnel) {
	t.mu.Lock()
	t.Status = StatusStarting
	t.Error = ""
	t.mu.Unlock()

	wpConf, err := m.generateWireproxyConfig(t)
	if err != nil {
		t.mu.Lock()
		t.Status = StatusError
		t.Error = fmt.Sprintf("config generation failed: %v", err)
		t.mu.Unlock()
		log.Printf("[tunnels] %s: %s", t.Name, t.Error)
		return
	}

	t.mu.Lock()
	t.tmpConf = wpConf
	t.done = make(chan struct{})
	t.mu.Unlock()

	cmd := exec.Command("wireproxy", "-c", wpConf)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		t.mu.Lock()
		t.Status = StatusError
		t.Error = fmt.Sprintf("failed to start wireproxy: %v", err)
		t.mu.Unlock()
		log.Printf("[tunnels] %s: %s", t.Name, t.Error)
		return
	}

	t.mu.Lock()
	t.cmd = cmd
	t.StartedAt = time.Now()
	t.Status = StatusRunning
	t.mu.Unlock()

	log.Printf("[tunnels] %s: started (pid %d, port %d)", t.Name, cmd.Process.Pid, t.ProxyPort)

	go m.monitorOutput(t, stdout, stderr)

	go func() {
		err := cmd.Wait()
		t.mu.Lock()
		if t.Status != StatusStopped {
			t.Status = StatusError
			if err != nil {
				t.Error = fmt.Sprintf("process exited: %v", err)
			} else {
				t.Error = "process exited unexpectedly"
			}
			log.Printf("[tunnels] %s: %s", t.Name, t.Error)
		}
		t.cmd = nil
		t.mu.Unlock()
		close(t.done)
	}()
}

func (m *Manager) stopTunnel(t *Tunnel) {
	t.mu.Lock()
	cmd := t.cmd
	done := t.done
	t.Status = StatusStopped
	t.Error = ""
	t.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(os.Interrupt)
		if done != nil {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
			}
		}
	}

	t.mu.RLock()
	if t.tmpConf != "" {
		os.Remove(t.tmpConf)
	}
	t.mu.RUnlock()

	log.Printf("[tunnels] %s: stopped", t.Name)
}

func (m *Manager) generateWireproxyConfig(t *Tunnel) (string, error) {
	srcData, err := os.ReadFile(t.ConfigPath)
	if err != nil {
		return "", fmt.Errorf("reading config: %w", err)
	}

	content := string(srcData)
	socks5Section := fmt.Sprintf("\n[Socks5]\nBindAddress = 127.0.0.1:%d\n", t.ProxyPort)
	content += socks5Section

	tmpFile, err := os.CreateTemp("", fmt.Sprintf("wg-proxy-%s-*.conf", t.Name))
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("writing config: %w", err)
	}
	tmpFile.Close()
	return tmpFile.Name(), nil
}

func (m *Manager) monitorOutput(t *Tunnel, stdout, stderr io.ReadCloser) {
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			log.Printf("[wireproxy/%s] %s", t.Name, scanner.Text())
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Printf("[wireproxy/%s] ERR: %s", t.Name, scanner.Text())
		}
	}()
}

// Disconnect stops the wireproxy process but keeps the .conf file.
func (m *Manager) Disconnect(name string) error {
	t := m.GetTunnel(name)
	if t == nil {
		return fmt.Errorf("tunnel %q not found", name)
	}
	m.stopTunnel(t)
	t.mu.Lock()
	t.Status = StatusDisconnected
	t.mu.Unlock()
	log.Printf("[tunnels] %s: disconnected", name)
	return nil
}

// Delete stops the wireproxy process and removes the .conf file.
func (m *Manager) Delete(name string) error {
	t := m.GetTunnel(name)
	if t == nil {
		return fmt.Errorf("tunnel %q not found", name)
	}
	m.stopTunnel(t)

	// Remove the config file
	if err := os.Remove(t.ConfigPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing config file: %w", err)
	}

	// Remove from tunnels list
	m.mu.Lock()
	for i, tun := range m.tunnels {
		if tun.Name == name {
			m.tunnels = append(m.tunnels[:i], m.tunnels[i+1:]...)
			break
		}
	}
	m.mu.Unlock()

	log.Printf("[tunnels] %s: deleted", name)
	return nil
}

// ImportConfig writes a new .conf file to the config directory and starts a tunnel for it.
func (m *Manager) ImportConfig(name string, confContent []byte) error {
	confPath := filepath.Join(m.configDir, name+".conf")

	if err := os.WriteFile(confPath, confContent, 0600); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	m.mu.Lock()
	tunnel := &Tunnel{
		Name:       name,
		ConfigPath: confPath,
		ProxyPort:  m.nextPort,
		Status:     StatusStopped,
		Country:    extractCountryFromName(name),
	}
	m.tunnels = append(m.tunnels, tunnel)
	m.nextPort++
	m.mu.Unlock()

	go m.startTunnel(tunnel)
	log.Printf("[tunnels] %s: imported and starting (port %d)", name, tunnel.ProxyPort)
	return nil
}

// ConfigDir returns the configuration directory path.
func (m *Manager) ConfigDir() string {
	return m.configDir
}

// extractCountryFromName attempts to extract a 2-letter country code from the tunnel name.
// It looks for patterns like "us-east", "de-west", etc.
func extractCountryFromName(name string) string {
	parts := strings.SplitN(name, "-", 2)
	if len(parts) >= 1 && len(parts[0]) == 2 {
		return strings.ToUpper(parts[0])
	}
	return ""
}
