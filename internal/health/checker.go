package health

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/xnet-admin/wg-proxy/internal/tunnels"
)

// TunnelHealth holds per-tunnel health status including traffic stats.
type TunnelHealth struct {
	Name       string        `json:"name"`
	Status     string        `json:"status"`
	Latency    time.Duration `json:"latency"`
	BytesIn    int64         `json:"bytes_in"`
	BytesOut   int64         `json:"bytes_out"`
	TotalConns int64         `json:"total_conns"`
	ExitIP     string        `json:"exit_ip,omitempty"`
}

// Stats holds aggregate health statistics.
type Stats struct {
	TotalChecks   int64
	HealthyCount  int
	TotalCount    int
	AvgLatency    time.Duration
	LastCheckTime time.Time
}

// Checker performs periodic health checks on all tunnels.
type Checker struct {
	manager   *tunnels.Manager
	interval  time.Duration
	timeout   time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
	mu        sync.RWMutex
	stats     Stats
	exitIPs   map[string]string // tunnel name -> exit IP
	ipMu      sync.RWMutex
	goldPorts []int // HTTPS-verified backends (gold pool)
	goldMu    sync.RWMutex
}

// NewChecker creates a new health checker.
func NewChecker(manager *tunnels.Manager, interval, timeout time.Duration) *Checker {
	return &Checker{
		manager:  manager,
		interval: interval,
		timeout:  timeout,
		stopCh:   make(chan struct{}),
		exitIPs:  make(map[string]string),
	}
}

// Start begins periodic health checking.
func (c *Checker) Start() {
	c.wg.Add(1)
	go c.loop()
	log.Printf("[health] Started (interval=%s, timeout=%s)", c.interval, c.timeout)
}

// Stop halts the health checker.
func (c *Checker) Stop() {
	close(c.stopCh)
	c.wg.Wait()
	log.Println("[health] Stopped")
}

// GetStats returns current health statistics.
func (c *Checker) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// GetTunnelHealth returns per-tunnel health information.
func (c *Checker) GetTunnelHealth(t *tunnels.Tunnel) TunnelHealth {
	t.RLock()
	th := TunnelHealth{
		Name:       t.Name,
		Status:     t.Status.String(),
		Latency:    t.Latency,
		BytesIn:    t.BytesIn.Load(),
		BytesOut:   t.BytesOut.Load(),
		TotalConns: t.ConnCount.Load(),
		ExitIP:     t.ExitIP,
	}
	t.RUnlock()
	return th
}

func (c *Checker) loop() {
	defer c.wg.Done()
	c.checkAll()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.checkAll()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Checker) checkAll() {
	tuns := c.manager.GetTunnels()
	var healthyCount int
	var totalLatency time.Duration

	for _, t := range tuns {
		t.RLock()
		status := t.Status
		t.RUnlock()

		if status == tunnels.StatusStopped || status == tunnels.StatusError || status == tunnels.StatusDisconnected {
			continue
		}

		latency, err := c.checkTunnel(t)

		t.Lock()
		t.LastCheck = time.Now()
		if err != nil {
			t.Status = tunnels.StatusUnhealthy
			t.Error = err.Error()
			t.Latency = 0
		} else {
			t.Status = tunnels.StatusRunning
			t.Error = ""
			t.Latency = latency
			healthyCount++
			totalLatency += latency

			// Resolve exit IP on first successful check
			if t.ExitIP == "" {
				go c.resolveExitIP(t)
			}
		}
		t.Unlock()
	}

	var avgLatency time.Duration
	if healthyCount > 0 {
		avgLatency = totalLatency / time.Duration(healthyCount)
	}

	c.mu.Lock()
	c.stats.TotalChecks++
	c.stats.HealthyCount = healthyCount
	c.stats.TotalCount = len(tuns)
	c.stats.AvgLatency = avgLatency
	c.stats.LastCheckTime = time.Now()
	c.mu.Unlock()

	// Run HTTPS deep check every 5th cycle to maintain gold pool
	if c.stats.TotalChecks%5 == 1 {
		go c.deepCheckAll()
	}
}

func (c *Checker) checkTunnel(t *tunnels.Tunnel) (time.Duration, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", t.ProxyPort)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, c.timeout)
	if err != nil {
		return 0, fmt.Errorf("tcp connect failed: %w", err)
	}
	conn.Close()
	return time.Since(start), nil
}

// resolveExitIP performs a request through the tunnel's SOCKS5 proxy to determine its exit IP.
func (c *Checker) resolveExitIP(t *tunnels.Tunnel) {
	addr := fmt.Sprintf("127.0.0.1:%d", t.ProxyPort)

	transport := &http.Transport{
		Dial: func(network, a string) (net.Conn, error) {
			// Connect to the SOCKS5 proxy
			proxyConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return nil, err
			}
			// SOCKS5 handshake
			proxyConn.Write([]byte{0x05, 0x01, 0x00})
			buf := make([]byte, 2)
			proxyConn.Read(buf)

			// CONNECT to ifconfig.me:80
			host := "ifconfig.me"
			req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
			req = append(req, []byte(host)...)
			req = append(req, 0x00, 0x50) // port 80
			proxyConn.Write(req)

			resp := make([]byte, 256)
			proxyConn.Read(resp)
			if len(resp) >= 2 && resp[1] != 0x00 {
				proxyConn.Close()
				return nil, fmt.Errorf("SOCKS5 connect failed")
			}
			return proxyConn, nil
		},
	}

	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := client.Get("http://ifconfig.me/ip")
	if err != nil {
		log.Printf("[health] %s: failed to resolve exit IP: %v", t.Name, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	ip := strings.TrimSpace(string(body))
	t.Lock()
	t.ExitIP = ip
	t.Unlock()
	log.Printf("[health] %s: exit IP resolved to %s", t.Name, ip)
}


// GetGoldPorts returns backends verified to pass HTTPS traffic.
func (c *Checker) GetGoldPorts() []int {
	c.goldMu.RLock()
	defer c.goldMu.RUnlock()
	result := make([]int, len(c.goldPorts))
	copy(result, c.goldPorts)
	return result
}

// deepCheckAll runs HTTPS-level verification on all healthy backends.
func (c *Checker) deepCheckAll() {
	tuns := c.manager.GetTunnels()
	var gold []int
	var dwg sync.WaitGroup
	var mu sync.Mutex

	// Check up to 50 concurrently
	sem := make(chan struct{}, 50)

	for _, t := range tuns {
		t.RLock()
		status := t.Status
		port := t.ProxyPort
		t.RUnlock()

		if status != tunnels.StatusRunning {
			continue
		}

		dwg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer dwg.Done()
			defer func() { <-sem }()
			if c.httpsProbe(p) {
				mu.Lock()
				gold = append(gold, p)
				mu.Unlock()
			}
		}(port)
	}

	dwg.Wait()

	c.goldMu.Lock()
	c.goldPorts = gold
	c.goldMu.Unlock()

	log.Printf("[health] Gold pool updated: %d/%d backends pass HTTPS", len(gold), len(tuns))
}

// httpsProbe verifies a backend can complete a real HTTPS request.
func (c *Checker) httpsProbe(port int) bool {
	// Use exec curl for a real end-to-end HTTPS test
	cmd := exec.Command("curl", "-s", "--proxy", fmt.Sprintf("socks5h://127.0.0.1:%d", port),
		"--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "200"
}
