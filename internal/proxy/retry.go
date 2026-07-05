package proxy

import (
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RetryProxy is a SOCKS5 proxy that retries failed connections across multiple backends.
type RetryProxy struct {
	addr       string
	backends   func() []int // returns list of healthy backend ports
	goldPool   func() []int // returns HTTPS-verified backends
	maxRetries int
	listener   net.Listener
	index      atomic.Uint64
	conns      atomic.Int64
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
}

// NewRetryProxy creates a retry-capable SOCKS5 proxy.
func NewRetryProxy(addr string, backends func() []int, goldPool func() []int) *RetryProxy {
	return &RetryProxy{
		addr:       addr,
		backends:   backends,
		goldPool:   goldPool,
		maxRetries: 5,
	}
}

func (rp *RetryProxy) ListenAndServe() error {
	ln, err := net.Listen("tcp", rp.addr)
	if err != nil {
		return err
	}
	rp.listener = ln
	log.Printf("[retry-proxy] Listening on %s (retries up to %d backends)", rp.addr, rp.maxRetries)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go rp.handleConn(conn)
	}
}

func (rp *RetryProxy) Close() {
	if rp.listener != nil {
		rp.listener.Close()
	}
}

func (rp *RetryProxy) Stats() (conns, bytesIn, bytesOut int64) {
	return rp.conns.Load(), rp.bytesIn.Load(), rp.bytesOut.Load()
}

func (rp *RetryProxy) handleConn(client net.Conn) {
	defer client.Close()
	rp.conns.Add(1)

	// SOCKS5 greeting
	buf := make([]byte, 258)
	n, err := client.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// No auth
	client.Write([]byte{0x05, 0x00})

	// SOCKS5 request
	n, err = client.Read(buf)
	if err != nil || n < 7 {
		return
	}

	// Save the full SOCKS5 request to replay to backends
	socksReq := make([]byte, n)
	copy(socksReq, buf[:n])

	// Get backends - prefer gold pool
	ports := rp.goldPool()
	if len(ports) == 0 {
		ports = rp.backends()
	}
	if len(ports) == 0 {
		// Send SOCKS5 failure
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Round-robin starting index
	startIdx := int(rp.index.Add(1)) % len(ports)

	// Try backends with retry
	var upstream net.Conn
	var socksReply []byte

	for attempt := 0; attempt < rp.maxRetries && attempt < len(ports); attempt++ {
		idx := (startIdx + attempt) % len(ports)
		port := ports[idx]

		upstream, socksReply, err = rp.tryBackend(port, socksReq)
		if err == nil {
			break
		}
		upstream = nil
	}

	if upstream == nil {
		// All retries failed
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer upstream.Close()

	// Send the successful SOCKS5 reply to client
	client.Write(socksReply)

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, client)
		rp.bytesIn.Add(n)
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, upstream)
		rp.bytesOut.Add(n)
	}()

	wg.Wait()
}

// tryBackend attempts to connect through a specific wireproxy backend.
func (rp *RetryProxy) tryBackend(port int, socksReq []byte) (net.Conn, []byte, error) {
	addr := net.JoinHostPort("127.0.0.1", itoa(port))

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, nil, err
	}

	conn.SetDeadline(time.Now().Add(8 * time.Second))

	// SOCKS5 greeting to backend
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[1] != 0x00 {
		conn.Close()
		return nil, nil, err
	}

	// Forward the original SOCKS5 CONNECT request
	conn.Write(socksReq)

	// Read SOCKS5 reply (variable length)
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, nil, err
	}

	if reply[1] != 0x00 {
		conn.Close()
		return nil, nil, net.UnknownNetworkError("socks5 connect failed")
	}

	// Read rest of reply based on address type
	var rest []byte
	switch reply[3] {
	case 0x01: // IPv4
		rest = make([]byte, 6)
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		rest = make([]byte, int(lenBuf[0])+2)
		reply = append(reply, lenBuf...)
	case 0x04: // IPv6
		rest = make([]byte, 18)
	default:
		rest = make([]byte, 6)
	}
	io.ReadFull(conn, rest)
	reply = append(reply, rest...)

	// Clear deadline for data transfer
	conn.SetDeadline(time.Time{})

	return conn, reply, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 5)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
