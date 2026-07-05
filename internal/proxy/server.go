package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xnet-admin/wg-proxy/internal/tunnels"
)

// Server is a SOCKS5 proxy that load-balances across healthy tunnel backends.
type Server struct {
	manager  *tunnels.Manager
	addr     string
	listener net.Listener
	closed   atomic.Bool
	mu       sync.Mutex
	counter  uint64
}

// NewServer creates a new SOCKS5 proxy server.
func NewServer(manager *tunnels.Manager, addr string) *Server {
	return &Server{
		manager: manager,
		addr:    addr,
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
		go s.handleConnection(conn)
	}
}

// Close stops the proxy server.
func (s *Server) Close() {
	s.closed.Store(true)
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// SOCKS5 greeting
	buf := make([]byte, 258)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// Respond: no auth required
	clientConn.Write([]byte{0x05, 0x00})

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
	backend, tunnel := s.pickBackend()
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
