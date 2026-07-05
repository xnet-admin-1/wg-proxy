package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/xnet-admin/wg-proxy/internal/health"
	"github.com/xnet-admin/wg-proxy/internal/tunnels"
)

//go:embed static/*
var staticFiles embed.FS

// Dashboard serves the admin web UI and SSE events.
type Dashboard struct {
	manager *tunnels.Manager
	checker *health.Checker

	sseMu   sync.Mutex
	clients map[chan []byte]struct{}
}

// NewDashboard creates a new dashboard instance.
func NewDashboard(manager *tunnels.Manager, checker *health.Checker) *Dashboard {
	d := &Dashboard{
		manager: manager,
		checker: checker,
		clients: make(map[chan []byte]struct{}),
	}
	go d.broadcastLoop()
	return d
}

// ServeDashboard serves the embedded HTML dashboard.
func (d *Dashboard) ServeDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "Dashboard not found", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// HandleSSE streams real-time tunnel status updates.
func (d *Dashboard) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan []byte, 8)
	d.sseMu.Lock()
	d.clients[ch] = struct{}{}
	d.sseMu.Unlock()
	defer func() {
		d.sseMu.Lock()
		delete(d.clients, ch)
		d.sseMu.Unlock()
	}()

	// Send initial state
	if data, err := json.Marshal(d.collectState()); err == nil {
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (d *Dashboard) broadcastLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		data, err := json.Marshal(d.collectState())
		if err != nil {
			continue
		}
		d.sseMu.Lock()
		for ch := range d.clients {
			select {
			case ch <- data:
			default:
			}
		}
		d.sseMu.Unlock()
	}
}

func (d *Dashboard) collectState() map[string]interface{} {
	tuns := d.manager.GetTunnels()
	stats := d.checker.GetStats()

	type tunnelState struct {
		Name      string `json:"name"`
		Status    string `json:"status"`
		Port      int    `json:"port"`
		LatencyMs int64  `json:"latency_ms"`
		Error     string `json:"error,omitempty"`
		BytesIn   int64  `json:"bytes_in"`
		BytesOut  int64  `json:"bytes_out"`
		ConnCount int64  `json:"conn_count"`
		Uptime    string `json:"uptime"`
	}

	tunnelStates := make([]tunnelState, 0, len(tuns))
	var totalIn, totalOut, totalConns int64

	for _, t := range tuns {
		t.RLock()
		ts := tunnelState{
			Name:      t.Name,
			Status:    t.Status.String(),
			Port:      t.ProxyPort,
			LatencyMs: t.Latency.Milliseconds(),
			Error:     t.Error,
			BytesIn:   t.BytesIn.Load(),
			BytesOut:  t.BytesOut.Load(),
			ConnCount: t.ConnCount.Load(),
		}
		if !t.StartedAt.IsZero() {
			ts.Uptime = time.Since(t.StartedAt).Round(time.Second).String()
		}
		t.RUnlock()
		totalIn += ts.BytesIn
		totalOut += ts.BytesOut
		totalConns += ts.ConnCount
		tunnelStates = append(tunnelStates, ts)
	}

	return map[string]interface{}{
		"tunnels":        tunnelStates,
		"healthy_count":  stats.HealthyCount,
		"total_count":    stats.TotalCount,
		"avg_latency_ms": stats.AvgLatency.Milliseconds(),
		"total_checks":   stats.TotalChecks,
		"total_bytes_in": totalIn,
		"total_bytes_out": totalOut,
		"total_conns":    totalConns,
	}
}

func init() {
	// Verify static files are embedded
	if _, err := staticFiles.ReadFile("static/index.html"); err != nil {
		log.Printf("[web] Warning: static/index.html not found in embed")
	}
}
