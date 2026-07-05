package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xnet-admin/wg-proxy/internal/health"
	"github.com/xnet-admin/wg-proxy/internal/proxy"
	"github.com/xnet-admin/wg-proxy/internal/tunnels"
	"github.com/xnet-admin/wg-proxy/internal/web"
	"github.com/xnet-admin/wg-proxy/internal/wgserver"
)

// RegisterRoutes sets up all HTTP routes.
func RegisterRoutes(mux *http.ServeMux, tm *tunnels.Manager, hc *health.Checker, dash *web.Dashboard, ps *proxy.Server, wgs *wgserver.Server, rc *wgserver.RoutingController) {
	mux.HandleFunc("/api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		handleTunnels(w, r, tm)
	})
	mux.HandleFunc("/api/tunnels/import", func(w http.ResponseWriter, r *http.Request) {
		handleImport(w, r, tm)
	})
	mux.HandleFunc("/api/tunnels/import-url", func(w http.ResponseWriter, r *http.Request) {
		handleImportURL(w, r, tm)
	})
	mux.HandleFunc("/api/tunnels/import-custom", func(w http.ResponseWriter, r *http.Request) {
		handleImportCustom(w, r, tm)
	})
	mux.HandleFunc("/api/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		handleTunnelAction(w, r, tm)
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		handleStats(w, r, tm, hc)
	})
	mux.HandleFunc("/api/countries", func(w http.ResponseWriter, r *http.Request) {
		handleCountries(w, r, ps)
	})
	mux.HandleFunc("/api/wg/status", func(w http.ResponseWriter, r *http.Request) {
		handleWGStatus(w, r, wgs)
	})
	mux.HandleFunc("/api/wg/peers", func(w http.ResponseWriter, r *http.Request) {
		handleWGPeers(w, r, wgs)
	})
	mux.HandleFunc("/api/wg/routing", func(w http.ResponseWriter, r *http.Request) {
		if rc != nil { handleRouting(w, r, rc) } else { writeJSON(w, http.StatusNotFound, map[string]string{"error": "routing not available"}) }
	})
	mux.HandleFunc("/api/wg/peers/", func(w http.ResponseWriter, r *http.Request) {
		handleWGPeerAction(w, r, wgs)
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
	// Parse: /api/tunnels/{name}/action or /api/tunnels/{name}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/tunnels/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "Not found", 404)
		return
	}

	name := parts[0]

	// DELETE /api/tunnels/{name}
	if r.Method == http.MethodDelete && len(parts) == 1 {
		if err := tm.Delete(name); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted", "name": name})
		return
	}

	if len(parts) < 2 {
		http.Error(w, "Not found", 404)
		return
	}

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
	case "disconnect":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", 405)
			return
		}
		if err := tm.Disconnect(name); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "disconnected", "name": name})
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

func handleImport(w http.ResponseWriter, r *http.Request, tm *tunnels.Manager) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid multipart form"})
		return
	}

	file, header, err := r.FormFile("config")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "missing 'config' file field"})
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "failed to read file"})
		return
	}

	name := strings.TrimSuffix(header.Filename, ".conf")
	if name == "" {
		writeJSON(w, 400, map[string]string{"error": "invalid filename"})
		return
	}

	if err := tm.ImportConfig(name, content); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, 200, map[string]string{"status": "imported", "name": name})
}

func handleImportURL(w http.ResponseWriter, r *http.Request, tm *tunnels.Manager) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		writeJSON(w, 400, map[string]string{"error": "missing or invalid 'url' field"})
		return
	}

	resp, err := http.Get(req.URL)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": fmt.Sprintf("failed to download: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeJSON(w, 500, map[string]string{"error": fmt.Sprintf("download returned status %d", resp.StatusCode)})
		return
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "failed to read response body"})
		return
	}

	// Extract name from URL path
	urlParts := strings.Split(req.URL, "/")
	filename := urlParts[len(urlParts)-1]
	name := strings.TrimSuffix(filename, ".conf")
	if name == "" {
		name = "imported"
	}

	if err := tm.ImportConfig(name, content); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, 200, map[string]string{"status": "imported", "name": name})
}

func handleImportCustom(w http.ResponseWriter, r *http.Request, tm *tunnels.Manager) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		Name               string `json:"name"`
		PrivateKey         string `json:"private_key"`
		Address            string `json:"address"`
		DNS                string `json:"dns"`
		PeerPubkey         string `json:"peer_pubkey"`
		Endpoint           string `json:"endpoint"`
		PersistentKeepalive int    `json:"persistent_keepalive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON body"})
		return
	}

	if req.Name == "" || req.PrivateKey == "" || req.Address == "" || req.PeerPubkey == "" || req.Endpoint == "" {
		writeJSON(w, 400, map[string]string{"error": "missing required fields"})
		return
	}

	if req.PersistentKeepalive == 0 {
		req.PersistentKeepalive = 25
	}

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = %d
`, req.PrivateKey, req.Address, req.DNS, req.PeerPubkey, req.Endpoint, req.PersistentKeepalive)

	if err := tm.ImportConfig(req.Name, []byte(conf)); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, 200, map[string]string{"status": "imported", "name": req.Name})
}

func handleCountries(w http.ResponseWriter, r *http.Request, ps *proxy.Server) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	writeJSON(w, 200, ps.GetCountryMapping())
}

func handleWGStatus(w http.ResponseWriter, r *http.Request, wgs *wgserver.Server) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if wgs == nil {
		writeJSON(w, 200, map[string]interface{}{"running": false, "enabled": false})
		return
	}
	writeJSON(w, 200, wgs.Status())
}

func handleWGPeers(w http.ResponseWriter, r *http.Request, wgs *wgserver.Server) {
	if wgs == nil {
		writeJSON(w, 503, map[string]string{"error": "WG server not enabled"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		peers := wgs.ListPeers()
		writeJSON(w, 200, peers)
	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			writeJSON(w, 400, map[string]string{"error": "missing or invalid 'name' field"})
			return
		}
		clientConf, err := wgs.AddPeer(req.Name)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"config":     clientConf,
			"config_ini": clientConf.ToINI(),
		})
	default:
		http.Error(w, "Method not allowed", 405)
	}
}

func handleWGPeerAction(w http.ResponseWriter, r *http.Request, wgs *wgserver.Server) {
	if wgs == nil {
		writeJSON(w, 503, map[string]string{"error": "WG server not enabled"})
		return
	}

	// Parse: /api/wg/peers/{name} or /api/wg/peers/{name}/config
	path := strings.TrimPrefix(r.URL.Path, "/api/wg/peers/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "Not found", 404)
		return
	}
	name := parts[0]

	// DELETE /api/wg/peers/{name}
	if r.Method == http.MethodDelete {
		if err := wgs.RemovePeer(name); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted", "name": name})
		return
	}

	// GET /api/wg/peers/{name}/config
	if r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "config" {
		conf, err := wgs.GetClientConfig(name)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.conf", name))
		w.WriteHeader(200)
		w.Write([]byte(conf.ToINI()))
		return
	}

	http.Error(w, "Not found", 404)
}

// handleRouting handles GET/POST /api/wg/routing
func handleRouting(w http.ResponseWriter, r *http.Request, rc *wgserver.RoutingController) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, rc.GetStatus())
		return
	}
	if r.Method == http.MethodPost {
		var req struct {
			Mode    string `json:"mode"`    // "direct" or "proxied"
			Country string `json:"country"` // optional country code
			Port    int    `json:"port"`    // optional specific wireproxy port
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		mode := wgserver.ModeDirect
		if req.Mode == "proxied" {
			mode = wgserver.ModeProxied
		}
		if err := rc.SetMode(mode, req.Country, req.Port); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, rc.GetStatus())
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
