package wgserver

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xnet-admin/wg-proxy/internal/config"
)

const (
	wgInterface = "wg-server"
	keyFile     = "server.key"
	pubKeyFile  = "server.pub"
)

// Server manages the WireGuard VPN server interface.
type Server struct {
	mu         sync.RWMutex
	cfg        *config.Config
	privateKey string
	publicKey  string
	running    bool
	peers      *PeerStore
	configDir  string
}

// NewServer creates a new WireGuard server instance.
func NewServer(cfg *config.Config) *Server {
	configDir := "/etc/wg-proxy"
	return &Server{
		cfg:       cfg,
		configDir: configDir,
		peers:     NewPeerStore(filepath.Join(configDir, "peers.json")),
	}
}

// Start initializes the WireGuard server interface.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	// Ensure config directory exists
	if err := os.MkdirAll(s.configDir, 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	// Load or generate keypair
	if err := s.loadOrGenerateKeys(); err != nil {
		return fmt.Errorf("loading keys: %w", err)
	}

	// Load existing peers
	if err := s.peers.Load(); err != nil {
		log.Printf("[wgserver] Warning: failed to load peers: %v", err)
	}

	// Create WireGuard interface
	if err := s.setupInterface(); err != nil {
		return fmt.Errorf("setting up interface: %w", err)
	}

	// Add existing peers to interface
	for _, p := range s.peers.List() {
		peer := p // copy for pointer
		if err := s.addPeerToInterface(&peer); err != nil {
			log.Printf("[wgserver] Warning: failed to add peer %s: %v", p.Name, err)
		}
	}

	// Setup NAT/masquerade
	if err := s.setupNAT(); err != nil {
		// Try to clean up
		s.teardownInterface()
		return fmt.Errorf("setting up NAT: %w", err)
	}

	s.running = true
	log.Printf("[wgserver] WireGuard server started on :%d (pubkey: %s...)", s.cfg.WGServerPort, s.publicKey[:8])
	return nil
}

// Stop tears down the WireGuard interface and NAT rules.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.teardownNAT()
	s.teardownInterface()
	s.running = false
	log.Println("[wgserver] WireGuard server stopped")
}

// PublicKey returns the server's public key.
func (s *Server) PublicKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publicKey
}

// IsRunning returns whether the server is active.
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// AddPeer creates a new client peer and returns its configuration.
func (s *Server) AddPeer(name string) (*ClientConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil, fmt.Errorf("wg server not running")
	}

	// Check for duplicate name
	if s.peers.Get(name) != nil {
		return nil, fmt.Errorf("peer %q already exists", name)
	}

	// Generate client keypair
	privKey, pubKey, err := generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating keypair: %w", err)
	}

	// Allocate IP from subnet
	ip, err := s.allocateIP()
	if err != nil {
		return nil, fmt.Errorf("allocating IP: %w", err)
	}

	peer := &Peer{
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: privKey,
		AllowedIP:  ip + "/32",
	}

	// Add to WireGuard interface
	if err := s.addPeerToInterface(peer); err != nil {
		return nil, fmt.Errorf("adding peer to interface: %w", err)
	}

	// Save to store
	if err := s.peers.Add(peer); err != nil {
		// Try to remove from interface on failure
		s.removePeerFromInterface(peer.PublicKey)
		return nil, fmt.Errorf("saving peer: %w", err)
	}

	// Build client config
	endpoint := s.cfg.WGServerAddr
	if endpoint == "" {
		endpoint = detectPublicIP()
	}
	if endpoint == "" {
		endpoint = "YOUR_SERVER_IP"
	}

	clientConf := &ClientConfig{
		Name:       name,
		PrivateKey: privKey,
		Address:    ip + "/32",
		DNS:        s.cfg.WGServerDNS,
		ServerPubKey: s.publicKey,
		Endpoint:   fmt.Sprintf("%s:%d", endpoint, s.cfg.WGServerPort),
		AllowedIPs: "0.0.0.0/0, ::/0",
	}

	log.Printf("[wgserver] Added peer %q (%s)", name, ip)
	return clientConf, nil
}

// RemovePeer removes a client peer.
func (s *Server) RemovePeer(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("wg server not running")
	}

	peer := s.peers.Get(name)
	if peer == nil {
		return fmt.Errorf("peer %q not found", name)
	}

	// Remove from WireGuard interface
	if err := s.removePeerFromInterface(peer.PublicKey); err != nil {
		log.Printf("[wgserver] Warning: failed to remove peer from interface: %v", err)
	}

	// Remove from store
	if err := s.peers.Remove(name); err != nil {
		return fmt.Errorf("removing peer from store: %w", err)
	}

	log.Printf("[wgserver] Removed peer %q", name)
	return nil
}

// ListPeers returns all configured peers.
func (s *Server) ListPeers() []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peers.List()
}

// GetPeer returns a single peer by name.
func (s *Server) GetPeer(name string) *Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peers.Get(name)
}

// GetClientConfig returns the WireGuard client config for a peer.
func (s *Server) GetClientConfig(name string) (*ClientConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peer := s.peers.Get(name)
	if peer == nil {
		return nil, fmt.Errorf("peer %q not found", name)
	}

	endpoint := s.cfg.WGServerAddr
	if endpoint == "" {
		endpoint = detectPublicIP()
	}
	if endpoint == "" {
		endpoint = "YOUR_SERVER_IP"
	}

	return &ClientConfig{
		Name:       name,
		PrivateKey: peer.PrivateKey,
		Address:    peer.AllowedIP,
		DNS:        s.cfg.WGServerDNS,
		ServerPubKey: s.publicKey,
		Endpoint:   fmt.Sprintf("%s:%d", endpoint, s.cfg.WGServerPort),
		AllowedIPs: "0.0.0.0/0, ::/0",
	}, nil
}

// Status returns the server status info.
func (s *Server) Status() ServerStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	endpoint := s.cfg.WGServerAddr
	if endpoint == "" {
		endpoint = detectPublicIP()
	}

	return ServerStatus{
		Running:   s.running,
		PublicKey: s.publicKey,
		Endpoint:  endpoint,
		Port:      s.cfg.WGServerPort,
		Subnet:    s.cfg.WGServerSubnet,
		PeerCount: len(s.peers.List()),
	}
}

// ServerStatus holds the WG server status information.
type ServerStatus struct {
	Running   bool   `json:"running"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
	Port      int    `json:"port"`
	Subnet    string `json:"subnet"`
	PeerCount int    `json:"peer_count"`
}

// ClientConfig holds the configuration for a WireGuard client.
type ClientConfig struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Address    string `json:"address"`
	DNS        string `json:"dns"`
	ServerPubKey string `json:"server_pubkey"`
	Endpoint   string `json:"endpoint"`
	AllowedIPs string `json:"allowed_ips"`
}

// ToINI returns the client configuration in WireGuard INI format.
func (c *ClientConfig) ToINI() string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, c.PrivateKey, c.Address, c.DNS, c.ServerPubKey, c.Endpoint, c.AllowedIPs)
}

// --- internal helpers ---

func (s *Server) loadOrGenerateKeys() error {
	keyPath := filepath.Join(s.configDir, keyFile)
	pubPath := filepath.Join(s.configDir, pubKeyFile)

	// Try to load existing keys
	privData, err := os.ReadFile(keyPath)
	if err == nil {
		s.privateKey = strings.TrimSpace(string(privData))
		pubData, err := os.ReadFile(pubPath)
		if err == nil {
			s.publicKey = strings.TrimSpace(string(pubData))
			return nil
		}
		// Regenerate public key from private key
		pub, err := derivePublicKey(s.privateKey)
		if err != nil {
			return err
		}
		s.publicKey = pub
		return os.WriteFile(pubPath, []byte(pub+"\n"), 0600)
	}

	// Generate new keypair
	priv, pub, err := generateKeyPair()
	if err != nil {
		return err
	}
	s.privateKey = priv
	s.publicKey = pub

	if err := os.WriteFile(keyPath, []byte(priv+"\n"), 0600); err != nil {
		return err
	}
	return os.WriteFile(pubPath, []byte(pub+"\n"), 0600)
}

func (s *Server) setupInterface() error {
	// Remove existing interface if any
	exec.Command("ip", "link", "del", wgInterface).Run()

	// Create the interface
	if out, err := exec.Command("ip", "link", "add", wgInterface, "type", "wireguard").CombinedOutput(); err != nil {
		return fmt.Errorf("creating interface: %s: %w", string(out), err)
	}

	// Write private key to temp file for wg set
	tmpKey, err := os.CreateTemp("", "wg-server-key-*")
	if err != nil {
		return fmt.Errorf("creating temp key file: %w", err)
	}
	tmpKey.WriteString(s.privateKey)
	tmpKey.Close()
	defer os.Remove(tmpKey.Name())

	// Configure the interface
	if out, err := exec.Command("wg", "set", wgInterface,
		"listen-port", fmt.Sprintf("%d", s.cfg.WGServerPort),
		"private-key", tmpKey.Name(),
	).CombinedOutput(); err != nil {
		return fmt.Errorf("configuring interface: %s: %w", string(out), err)
	}

	// Assign the server IP (first IP in subnet)
	serverIP := s.getServerIP()
	_, ipNet, err := net.ParseCIDR(s.cfg.WGServerSubnet)
	if err != nil {
		return fmt.Errorf("parsing subnet: %w", err)
	}
	ones, _ := ipNet.Mask.Size()
	addr := fmt.Sprintf("%s/%d", serverIP, ones)

	if out, err := exec.Command("ip", "addr", "add", addr, "dev", wgInterface).CombinedOutput(); err != nil {
		// Ignore if already assigned
		if !strings.Contains(string(out), "RTNETLINK answers: File exists") {
			return fmt.Errorf("assigning address: %s: %w", string(out), err)
		}
	}

	// Bring up the interface
	if out, err := exec.Command("ip", "link", "set", wgInterface, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("bringing up interface: %s: %w", string(out), err)
	}

	return nil
}

func (s *Server) teardownInterface() {
	exec.Command("ip", "link", "del", wgInterface).Run()
}

func (s *Server) setupNAT() error {
	// Enable IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("enabling ip_forward: %w", err)
	}

	// Add MASQUERADE rule for traffic from the WG subnet
	subnet := s.cfg.WGServerSubnet
	if out, err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", subnet, "-o", getDefaultInterface(), "-j", "MASQUERADE").CombinedOutput(); err != nil {
		return fmt.Errorf("adding MASQUERADE rule: %s: %w", string(out), err)
	}

	// Allow forwarding from wg-server
	if out, err := exec.Command("iptables", "-A", "FORWARD",
		"-i", wgInterface, "-j", "ACCEPT").CombinedOutput(); err != nil {
		return fmt.Errorf("adding FORWARD accept in: %s: %w", string(out), err)
	}

	// Allow forwarding back to wg-server (established/related)
	if out, err := exec.Command("iptables", "-A", "FORWARD",
		"-o", wgInterface, "-m", "state", "--state", "RELATED,ESTABLISHED",
		"-j", "ACCEPT").CombinedOutput(); err != nil {
		return fmt.Errorf("adding FORWARD accept out: %s: %w", string(out), err)
	}

	return nil
}

func (s *Server) teardownNAT() {
	subnet := s.cfg.WGServerSubnet
	defaultIface := getDefaultInterface()

	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", subnet, "-o", defaultIface, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD",
		"-i", wgInterface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD",
		"-o", wgInterface, "-m", "state", "--state", "RELATED,ESTABLISHED",
		"-j", "ACCEPT").Run()
}

func (s *Server) addPeerToInterface(p *Peer) error {
	if out, err := exec.Command("wg", "set", wgInterface,
		"peer", p.PublicKey,
		"allowed-ips", p.AllowedIP,
	).CombinedOutput(); err != nil {
		return fmt.Errorf("wg set peer: %s: %w", string(out), err)
	}
	return nil
}

func (s *Server) removePeerFromInterface(pubKey string) error {
	if out, err := exec.Command("wg", "set", wgInterface,
		"peer", pubKey, "remove",
	).CombinedOutput(); err != nil {
		return fmt.Errorf("wg remove peer: %s: %w", string(out), err)
	}
	return nil
}

func (s *Server) getServerIP() string {
	_, ipNet, err := net.ParseCIDR(s.cfg.WGServerSubnet)
	if err != nil {
		return "10.100.0.1"
	}
	// Server gets .1 in the subnet
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)
	ip[len(ip)-1] = 1
	return ip.String()
}

func (s *Server) allocateIP() (string, error) {
	_, ipNet, err := net.ParseCIDR(s.cfg.WGServerSubnet)
	if err != nil {
		return "", fmt.Errorf("parsing subnet: %w", err)
	}

	// Collect used IPs
	used := make(map[string]bool)
	used[s.getServerIP()] = true
	for _, p := range s.peers.List() {
		ip := strings.Split(p.AllowedIP, "/")[0]
		used[ip] = true
	}

	// Find next available IP (start from .2)
	baseIP := make(net.IP, len(ipNet.IP))
	copy(baseIP, ipNet.IP)

	for i := 2; i < 254; i++ {
		candidate := make(net.IP, len(baseIP))
		copy(candidate, baseIP)
		candidate[len(candidate)-1] = byte(i)
		if ipNet.Contains(candidate) && !used[candidate.String()] {
			return candidate.String(), nil
		}
	}

	return "", fmt.Errorf("no available IPs in subnet %s", s.cfg.WGServerSubnet)
}

// --- crypto helpers ---

func generateKeyPair() (privateKey, publicKey string, err error) {
	// Generate private key: 32 random bytes, base64 encoded
	// Then clamp per Curve25519 rules
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", "", fmt.Errorf("generating random bytes: %w", err)
	}
	// Clamp the private key for Curve25519
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	privKey := base64.StdEncoding.EncodeToString(key[:])

	// Derive public key using wg tool
	pubKey, err2 := derivePublicKey(privKey)
	if err2 != nil {
		return "", "", err2
	}

	return privKey, pubKey, nil
}

func derivePublicKey(privateKey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("deriving public key: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// getDefaultInterface returns the name of the default route interface.
func getDefaultInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "eth0"
	}
	// Parse: "default via X.X.X.X dev ethN ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return "eth0"
}

// detectPublicIP tries to determine the server's public IP.
func detectPublicIP() string {
	// Try to get from default route interface
	iface := getDefaultInterface()
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return ""
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}
