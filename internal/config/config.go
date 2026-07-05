package config

import (
	"os"
	"time"
)

// Config holds the application configuration.
type Config struct {
	ConfigDir       string        // Directory containing .conf files
	ProxyAddr       string        // SOCKS5 proxy listen address
	AdminAddr       string        // Admin dashboard listen address
	BasePort        int           // Starting port for wireproxy SOCKS5 backends
	HealthInterval  time.Duration // Health check interval
	HealthTimeout   time.Duration // Health check timeout
	HealthURL       string        // Optional HTTP URL to check through each tunnel
	ProxyUser       string        // SOCKS5 proxy username (optional)
	ProxyPass       string        // SOCKS5 proxy password (optional)
	CountryPortBase int           // Starting port for per-country SOCKS5 proxies
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		ConfigDir:       envOrDefault("WG_CONFIG_DIR", "/etc/wg-proxy/configs"),
		ProxyAddr:       envOrDefault("WG_PROXY_ADDR", ":1080"),
		AdminAddr:       envOrDefault("WG_ADMIN_ADDR", ":8080"),
		BasePort:        envOrDefaultInt("WG_BASE_PORT", 10001),
		HealthInterval:  envOrDefaultDuration("WG_HEALTH_INTERVAL", 10*time.Second),
		HealthTimeout:   envOrDefaultDuration("WG_HEALTH_TIMEOUT", 5*time.Second),
		HealthURL:       envOrDefault("WG_HEALTH_URL", ""),
		ProxyUser:       envOrDefault("WG_PROXY_USER", ""),
		ProxyPass:       envOrDefault("WG_PROXY_PASS", ""),
		CountryPortBase: envOrDefaultInt("WG_COUNTRY_PORT_BASE", 1081),
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrDefaultInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	if n == 0 {
		return def
	}
	return n
}

func envOrDefaultDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
