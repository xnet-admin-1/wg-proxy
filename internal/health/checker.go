package health

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xnet-admin/wg-proxy/internal/tunnels"
)

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
	manager  *tunnels.Manager
	interval time.Duration
	timeout  time.Duration
	stopCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
	stats    Stats
}

// NewChecker creates a new health checker.
func NewChecker(manager *tunnels.Manager, interval, timeout time.Duration) *Checker {
	return &Checker{
		manager:  manager,
		interval: interval,
		timeout:  timeout,
		stopCh:   make(chan struct{}),
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

		if status == tunnels.StatusStopped || status == tunnels.StatusError {
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
