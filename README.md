# WG-Proxy

A WireGuard proxy gateway that manages multiple WireGuard tunnels (using [wireproxy](https://github.com/pufferffish/wireproxy) as the userspace implementation) and exposes them as a SOCKS5 proxy pool with round-robin load balancing and a real-time web admin dashboard.

## Features

- **Multi-tunnel management** — loads WireGuard `.conf` files from a directory, each spawning a wireproxy subprocess
- **SOCKS5 proxy pool** — main proxy on `:1080` distributes connections round-robin across healthy backends
- **Health monitoring** — periodic TCP connect checks with latency tracking
- **Real-time dashboard** — dark-themed web UI on `:8080` with SSE live updates
- **Traffic counters** — per-tunnel bytes in/out and connection counts
- **Graceful lifecycle** — clean start/stop/restart of individual tunnels or all at once
- **Single binary** — embedded static assets, no external dependencies beyond wireproxy
- **Docker-ready** — multi-stage Alpine build, ~20MB image

## Quick Start

### Docker (recommended)

```bash
docker build -t wg-proxy .
docker run -d --name wg-proxy \
  -p 1080:1080 \
  -p 8080:8080 \
  -v /path/to/configs:/etc/wg-proxy/configs \
  wg-proxy
```

### From source

```bash
go build -o wg-proxy ./cmd/wg-proxy/
./wg-proxy
```

Requires `wireproxy` in PATH. Install from [github.com/pufferffish/wireproxy](https://github.com/pufferffish/wireproxy/releases).

### Test it

```bash
# Dashboard
open http://localhost:8080

# Use the proxy
curl --proxy socks5h://localhost:1080 https://ifconfig.me

# API
curl http://localhost:8080/api/tunnels
curl http://localhost:8080/api/stats
curl -X POST http://localhost:8080/api/tunnels/us-east/restart
```

## Configuration

Place standard WireGuard `.conf` files in the config directory. Each file spawns a wireproxy instance on a sequential port starting from the base port.

Example `us-east.conf`:
```ini
[Interface]
PrivateKey = <your-private-key>
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `WG_CONFIG_DIR` | `/etc/wg-proxy/configs` | Directory containing `.conf` files |
| `WG_PROXY_ADDR` | `:1080` | SOCKS5 proxy listen address |
| `WG_ADMIN_ADDR` | `:8080` | Admin dashboard listen address |
| `WG_BASE_PORT` | `10001` | Starting port for wireproxy backends |
| `WG_HEALTH_INTERVAL` | `10s` | Health check interval |
| `WG_HEALTH_TIMEOUT` | `5s` | Health check timeout |
| `WG_HEALTH_URL` | *(empty)* | Optional HTTP URL to check through each tunnel |

## Project Structure

```
cmd/
  wg-proxy/          # Main entry point
internal/
  config/            # Configuration management
  tunnels/           # wireproxy process management
  proxy/             # SOCKS5 proxy with load balancing
  health/            # Health check monitoring
  handlers/          # HTTP API routes
  web/               # Embedded admin dashboard
    static/          # HTML/CSS/JS assets
configs/             # Example WireGuard configs
```

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Admin dashboard |
| `/api/tunnels` | GET | List all tunnels with status |
| `/api/tunnels/:name/restart` | POST | Restart a specific tunnel |
| `/api/stats` | GET | Aggregate statistics |
| `/api/events` | GET | SSE stream of real-time updates |

## How It Works

1. On startup, WG-Proxy scans the config directory for `.conf` files
2. For each config, it generates a wireproxy-compatible config (appends a `[Socks5]` section)
3. Each wireproxy subprocess exposes a local SOCKS5 proxy (ports 10001, 10002, ...)
4. The main SOCKS5 proxy on `:1080` accepts connections and forwards them round-robin to healthy backends
5. A health checker periodically verifies each backend is responsive
6. The dashboard provides real-time visibility via Server-Sent Events

## License

MIT
