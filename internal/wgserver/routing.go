package wgserver

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

// RoutingMode defines how WG client traffic is routed.
type RoutingMode string

const (
	ModeDirect  RoutingMode = "direct"  // Traffic goes out server's public IP
	ModeProxied RoutingMode = "proxied" // Traffic goes through wireproxy → Proton exits
)

// RoutingController manages how VPN client traffic is routed.
type RoutingController struct {
	mu          sync.RWMutex
	mode        RoutingMode
	exitCountry string // empty = round-robin all, "NL"/"US" etc = country-specific port
	proxyPort   int    // which wireproxy backend port to use
}

// NewRoutingController creates a routing controller.
func NewRoutingController() *RoutingController {
	return &RoutingController{
		mode:      ModeDirect,
		proxyPort: 10001,
	}
}

// GetMode returns the current routing mode.
func (rc *RoutingController) GetMode() RoutingMode {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.mode
}

// GetStatus returns routing status.
func (rc *RoutingController) GetStatus() map[string]interface{} {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return map[string]interface{}{
		"mode":         string(rc.mode),
		"exit_country": rc.exitCountry,
		"proxy_port":   rc.proxyPort,
	}
}

// SetMode changes the routing mode.
func (rc *RoutingController) SetMode(mode RoutingMode, country string, port int) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if mode == ModeProxied {
		if port == 0 {
			port = 10001
		}
		if err := rc.enableProxiedMode(port); err != nil {
			return err
		}
		rc.mode = ModeProxied
		rc.exitCountry = country
		rc.proxyPort = port
		log.Printf("[routing] Switched to PROXIED mode (port %d, country: %s)", port, country)
	} else {
		if err := rc.enableDirectMode(); err != nil {
			return err
		}
		rc.mode = ModeDirect
		rc.exitCountry = ""
		rc.proxyPort = 0
		log.Printf("[routing] Switched to DIRECT mode")
	}
	return nil
}

func (rc *RoutingController) enableProxiedMode(proxyPort int) error {
	cmds := []string{
		// Remove direct masquerade if exists
		"iptables -t nat -D POSTROUTING -s 10.100.0.0/24 -j MASQUERADE 2>/dev/null || true",
		// Flush and recreate WG_PROXY chain
		"iptables -t nat -F WG_PROXY 2>/dev/null || true",
		"iptables -t nat -N WG_PROXY 2>/dev/null || true",
		// Skip private ranges
		"iptables -t nat -A WG_PROXY -d 0.0.0.0/8 -j RETURN",
		"iptables -t nat -A WG_PROXY -d 10.0.0.0/8 -j RETURN",
		"iptables -t nat -A WG_PROXY -d 127.0.0.0/8 -j RETURN",
		"iptables -t nat -A WG_PROXY -d 169.254.0.0/16 -j RETURN",
		"iptables -t nat -A WG_PROXY -d 172.16.0.0/12 -j RETURN",
		"iptables -t nat -A WG_PROXY -d 192.168.0.0/16 -j RETURN",
		"iptables -t nat -A WG_PROXY -d 224.0.0.0/4 -j RETURN",
		"iptables -t nat -A WG_PROXY -d 240.0.0.0/4 -j RETURN",
		// Redirect TCP to redsocks
		"iptables -t nat -A WG_PROXY -p tcp -j REDIRECT --to-ports 12345",
		// Ensure PREROUTING has our chain
		"iptables -t nat -C PREROUTING -i wg-server -p tcp -j WG_PROXY 2>/dev/null || iptables -t nat -A PREROUTING -i wg-server -p tcp -j WG_PROXY",
		// DNS redirect
		"iptables -t nat -C PREROUTING -i wg-server -p udp --dport 53 -j DNAT --to-destination 1.1.1.1:53 2>/dev/null || iptables -t nat -A PREROUTING -i wg-server -p udp --dport 53 -j DNAT --to-destination 1.1.1.1:53",
		// Masquerade for outbound
		"iptables -t nat -C POSTROUTING -o ens5 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ens5 -j MASQUERADE",
		// Update redsocks config
		fmt.Sprintf(`cat > /etc/redsocks.conf << 'RCONF'
base {
    log_debug = off;
    log_info = on;
    log = "syslog:daemon";
    daemon = on;
    redirector = iptables;
}
redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;
    ip = 127.0.0.1;
    port = %d;
    type = socks5;
}
RCONF`, proxyPort),
		// Restart redsocks
		"systemctl restart redsocks",
	}
	return runCmds(cmds)
}

func (rc *RoutingController) enableDirectMode() error {
	cmds := []string{
		// Remove proxy chain from PREROUTING
		"iptables -t nat -D PREROUTING -i wg-server -p tcp -j WG_PROXY 2>/dev/null || true",
		"iptables -t nat -D PREROUTING -i wg-server -p udp --dport 53 -j DNAT --to-destination 1.1.1.1:53 2>/dev/null || true",
		// Flush proxy chain
		"iptables -t nat -F WG_PROXY 2>/dev/null || true",
		// Add simple masquerade
		"iptables -t nat -C POSTROUTING -s 10.100.0.0/24 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.100.0.0/24 -j MASQUERADE",
		// Stop redsocks
		"systemctl stop redsocks 2>/dev/null || true",
	}
	return runCmds(cmds)
}

func runCmds(cmds []string) error {
	for _, c := range cmds {
		cmd := exec.Command("bash", "-c", c)
		if out, err := cmd.CombinedOutput(); err != nil {
			outStr := strings.TrimSpace(string(out))
			if outStr != "" {
				log.Printf("[routing] cmd failed: %s → %s", c, outStr)
			}
		}
	}
	return nil
}
