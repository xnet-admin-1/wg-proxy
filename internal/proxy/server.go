package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xnet-admin/wg-proxy/internal/config"
	"github.com/xnet-admin/wg-proxy/internal/tunnels"
)

// Server is a SOCKS5 proxy that load-balances across healthy tunnel backends.
type Server struct {
	manager  *tunnels.Manager
	cfg      *config.Config
	addr     string
	listener net.Listener
	closed   atomic.Bool
	mu       sync.Mutex
	counter  uint64

	countryMu       sync.RWMutex
	countryMapping  map[string]int // country code -> port
	countryListeners []net.Listener
}

// NewServer creates a new SOCKS5 proxy server.
func NewServer(manager *tunnels.Manager, addr string, cfg *config.Config) *Server {
	return &Server{
		manager:        manager,
		addr:           addr,
		cfg:            cfg,
		countryMapping: make(map[string]int),
	}
}

// ListenAndServe starts the SOCKS5 proxy server.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}
	s.listener = ln

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			log.Printf("[proxy] Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn, nil)
	}
}

// Close stops the proxy server.
func (s *Server) Close() {
	s.closed.Store(true)
	if s.listener != nil {
		s.listener.Close()
	}
	s.countryMu.RLock()
	for _, ln := range s.countryListeners {
		ln.Close()
	}
	s.countryMu.RUnlock()
}

// GetCountryMapping returns the current country-to-port mapping.
func (s *Server) GetCountryMapping() map[string]int {
	s.countryMu.RLock()
	defer s.countryMu.RUnlock()
	result := make(map[string]int, len(s.countryMapping))
	for k, v := range s.countryMapping {
		result[k] = v
	}
	return result
}

// StartCountryProxies groups tunnels by country code and starts a SOCKS5 listener per country.
func (s *Server) StartCountryProxies() {
	tuns := s.manager.GetTunnels()
	countries := make(map[string][]*tunnels.Tunnel)
	for _, t := range tuns {
		t.RLock()
		country := t.Country
		t.RUnlock()
		if country != "" {
			countries[country] = append(countries[country], t)
		}
	}

	port := s.cfg.CountryPortBase
	s.countryMu.Lock()
	for country, countryTunnels := range countries {
		s.countryMapping[country] = port
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Printf("[proxy] Failed to start country proxy for %s on port %d: %v", country, port, err)
			port++
			continue
		}
		s.countryListeners = append(s.countryListeners, ln)
		log.Printf("[proxy] Country %s proxy listening on :%d (%d tunnels)", country, port, len(countryTunnels))

		go s.serveCountryProxy(ln, countryTunnels)
		port++
	}
	s.countryMu.Unlock()
}

func (s *Server) serveCountryProxy(ln net.Listener, countryTunnels []*tunnels.Tunnel) {
	var counter uint64
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue
		}
		go s.handleConnection(conn, &countryBackendPicker{
			tunnels: countryTunnels,
			counter: &counter,
		})
	}
}

type countryBackendPicker struct {
	tunnels []*tunnels.Tunnel
	counter *uint64
	mu      sync.Mutex
}

func (p *countryBackendPicker) pick() (string, *tunnels.Tunnel) {
	var healthy []*tunnels.Tunnel
	for _, t := range p.tunnels {
		if t.IsHealthy() {
			healthy = append(healthy, t)
		}
	}
	if len(healthy) == 0 {
		return "", nil
	}
	p.mu.Lock()
	idx := *p.counter % uint64(len(healthy))
	*p.counter++
	p.mu.Unlock()
	t := healthy[idx]
	return fmt.Sprintf("127.0.0.1:%d", t.ProxyPort), t
}

func (s *Server) handleConnection(clientConn net.Conn, picker *countryBackendPicker) {
	defer clientConn.Close()

	// SOCKS5 greeting
	buf := make([]byte, 258)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// Check if authentication is required
	if s.cfg.ProxyUser != "" && s.cfg.ProxyPass != "" {
		// Require username/password auth (RFC 1929)
		clientConn.Write([]byte{0x05, 0x02}) // method: username/password

		// Read auth request
		n, err = clientConn.Read(buf)
		if err != nil || n < 5 || buf[0] != 0x01 {
			clientConn.Write([]byte{0x01, 0x01}) // auth failure
			return
		}

		ulen := int(buf[1])
		if n < 2+ulen+1 {
			clientConn.Write([]byte{0x01, 0x01})
			return
		}
		username := string(buf[2 : 2+ulen])
		plen := int(buf[2+ulen])
		if n < 2+ulen+1+plen {
			clientConn.Write([]byte{0x01, 0x01})
			return
		}
		password := string(buf[2+ulen+1 : 2+ulen+1+plen])

		if username != s.cfg.ProxyUser || password != s.cfg.ProxyPass {
			clientConn.Write([]byte{0x01, 0x01}) // auth failure
			return
		}
		clientConn.Write([]byte{0x01, 0x00}) // auth success
	} else {
		// No auth required
		clientConn.Write([]byte{0x05, 0x00})
	}

	// Read connect request
	n, err = clientConn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Save the original request for forwarding
	connectReq := make([]byte, n)
	copy(connectReq, buf[:n])

	// Parse destination for logging
	target := parseTarget(buf[:n])

	// Pick a healthy backend
	var backend string
	var tunnel *tunnels.Tunnel
	if picker != nil {
		backend, tunnel = picker.pick()
	} else {
		backend, tunnel = s.pickBackend()
	}
	if backend == "" {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Printf("[proxy] No healthy backends for %s", target)
		return
	}

	// Connect to backend
	backendConn, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Printf("[proxy] Backend connect failed %s: %v", backend, err)
		return
	}
	defer backendConn.Close()

	// SOCKS5 handshake with backend
	if err := s.backendHandshake(backendConn, connectReq); err != nil {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Printf("[proxy] Backend handshake failed: %v", err)
		return
	}

	// Read backend response
	resp := make([]byte, 256)
	rn, err := backendConn.Read(resp)
	if err != nil || rn < 2 || resp[1] != 0x00 {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Success to client
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	if tunnel != nil {
		tunnel.ConnCount.Add(1)
	}

	// Bidirectional relay
	relay(clientConn, backendConn, tunnel)
}

func (s *Server) backendHandshake(conn net.Conn, connectReq []byte) error {
	// Greeting
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("unexpected auth: %x", buf)
	}
	// Forward connect request
	if _, err := conn.Write(connectReq); err != nil {
		return err
	}
	return nil
}

func (s *Server) pickBackend() (string, *tunnels.Tunnel) {
	all := s.manager.GetTunnels()
	var healthy []*tunnels.Tunnel
	for _, t := range all {
		if t.IsHealthy() {
			healthy = append(healthy, t)
		}
	}
	if len(healthy) == 0 {
		return "", nil
	}
	s.mu.Lock()
	idx := s.counter % uint64(len(healthy))
	s.counter++
	s.mu.Unlock()

	t := healthy[idx]
	return fmt.Sprintf("127.0.0.1:%d", t.ProxyPort), t
}

func parseTarget(buf []byte) string {
	if len(buf) < 7 {
		return "unknown"
	}
	switch buf[3] {
	case 0x01:
		if len(buf) >= 10 {
			return fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7], int(buf[8])<<8|int(buf[9]))
		}
	case 0x03:
		addrLen := int(buf[4])
		if len(buf) >= 5+addrLen+2 {
			port := int(buf[5+addrLen])<<8 | int(buf[5+addrLen+1])
			return fmt.Sprintf("%s:%d", string(buf[5:5+addrLen]), port)
		}
	}
	return "unknown"
}

func relay(client, backend net.Conn, tunnel *tunnels.Tunnel) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(backend, client)
		if tunnel != nil {
			tunnel.BytesOut.Add(n)
		}
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, backend)
		if tunnel != nil {
			tunnel.BytesIn.Add(n)
		}
	}()

	wg.Wait()
}
