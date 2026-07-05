package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/xnet-admin/wg-proxy/internal/health"
	"github.com/xnet-admin/wg-proxy/internal/tunnels"
	"github.com/xnet-admin/wg-proxy/internal/web"
)

// RegisterRoutes sets up all HTTP routes.
func RegisterRoutes(mux *http.ServeMux, tm *tunnels.Manager, hc *health.Checker, dash *web.Dashboard) {
	mux.HandleFunc("/api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		handleTunnels(w, r, tm)
	})
	mux.HandleFunc("/api/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		handleTunnelAction(w, r, tm)
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		handleStats(w, r, tm, hc)
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		dash.HandleSSE(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dash.ServeDashboard(w, r)
	})
}

func handleTunnels(w http.ResponseWriter, r *http.Request, tm *tunnels.Manager) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}

	tuns := tm.GetTunnels()
	type tunnelInfo struct {
		Name      string `json:"name"`
		Status    string `json:"status"`
		Port      int    `json:"port"`
		Latency   string `json:"latency"`
		Error     string `json:"error,omitempty"`
		BytesIn   int64  `json:"bytes_in"`
		BytesOut  int64  `json:"bytes_out"`
		ConnCount int64  `json:"conn_count"`
		Uptime    string `json:"uptime,omitempty"`
	}

	result := make([]tunnelInfo, 0, len(tuns))
	for _, t := range tuns {
		t.RLock()
		info := tunnelInfo{
			Name:      t.Name,
			Status:    t.Status.String(),
			Port:      t.ProxyPort,
			Latency:   t.Latency.Round(time.Millisecond).String(),
			Error:     t.Error,
			BytesIn:   t.BytesIn.Load(),
			BytesOut:  t.BytesOut.Load(),
			ConnCount: t.ConnCount.Load(),
		}
		if !t.StartedAt.IsZero() && t.Status != tunnels.StatusStopped {
			info.Uptime = time.Since(t.StartedAt).Round(time.Second).String()
		}
		t.RUnlock()
		result = append(result, info)
	}

	writeJSON(w, 200, result)
}

func handleTunnelAction(w http.ResponseWriter, r *http.Request, tm *tunnels.Manager) {
	// Parse: /api/tunnels/{name}/restart
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/tunnels/"), "/")
	if len(parts) < 2 {
		http.Error(w, "Not found", 404)
		return
	}

	name := parts[0]
	action := parts[1]

	switch action {
	case "restart":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", 405)
			return
		}
		if err := tm.Restart(name); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "restarting", "name": name})
	default:
		http.Error(w, "Unknown action", 404)
	}
}

func handleStats(w http.ResponseWriter, r *http.Request, tm *tunnels.Manager, hc *health.Checker) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}

	stats := hc.GetStats()
	tuns := tm.GetTunnels()

	var totalBytesIn, totalBytesOut, totalConns int64
	for _, t := range tuns {
		totalBytesIn += t.BytesIn.Load()
		totalBytesOut += t.BytesOut.Load()
		totalConns += t.ConnCount.Load()
	}

	writeJSON(w, 200, map[string]interface{}{
		"total_tunnels":   stats.TotalCount,
		"healthy_tunnels": stats.HealthyCount,
		"avg_latency":     stats.AvgLatency.Round(time.Millisecond).String(),
		"total_checks":    stats.TotalChecks,
		"last_check":      stats.LastCheckTime.Format(time.RFC3339),
		"total_bytes_in":  totalBytesIn,
		"total_bytes_out": totalBytesOut,
		"total_conns":     totalConns,
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
