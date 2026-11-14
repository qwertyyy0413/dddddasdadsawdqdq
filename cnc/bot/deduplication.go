package bot

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"overbyte-cnc/logger"
)

type DedupShard struct {
	active map[string]*Bot
	mutex  sync.RWMutex
}

type IPShard struct {
	ipToFingerprint map[string]string
	mutex           sync.RWMutex
}

type DeduplicationSystem struct {
	shards       [256]*DedupShard
	ipShards     [256]*IPShard
	totalBlocked int
	blockMutex   sync.Mutex
	enabled      bool
	replaceOld   bool
}

func (ds *DeduplicationSystem) getDedupShard(key string) *DedupShard {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return ds.shards[h%256]
}

func (ds *DeduplicationSystem) getIPShard(key string) *IPShard {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return ds.ipShards[h%256]
}

func NewDeduplicationSystem(enabled bool, replaceOld bool) *DeduplicationSystem {
	ds := &DeduplicationSystem{
		enabled:    enabled,
		replaceOld: replaceOld,
	}
	for i := 0; i < 256; i++ {
		ds.shards[i] = &DedupShard{active: make(map[string]*Bot)}
		ds.ipShards[i] = &IPShard{ipToFingerprint: make(map[string]string)}
	}
	return ds
}

func (ds *DeduplicationSystem) GenerateFingerprint(bot *Bot) string {
	data := fmt.Sprintf("%s|%s|%d|%d|%s",
		extractIP(bot.Addr),
		bot.Arch,
		bot.CPUCores,
		bot.TotalRAM,
		bot.Kernel,
	)

	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16])
}

func (ds *DeduplicationSystem) IsDuplicate(fingerprint string, currentBotAddr string) (bool, *Bot) {
	if !ds.enabled {
		return false, nil
	}

	shard := ds.getDedupShard(fingerprint)
	shard.mutex.RLock()
	defer shard.mutex.RUnlock()

	existingBot, exists := shard.active[fingerprint]
	if !exists {
		return false, nil
	}

	if existingBot.Addr == currentBotAddr {
		return false, nil
	}

	return true, existingBot
}

func (ds *DeduplicationSystem) RegisterBot(fingerprint string, bot *Bot) bool {
	if !ds.enabled {
		return true
	}

	shard := ds.getDedupShard(fingerprint)
	shard.mutex.Lock()
	defer shard.mutex.Unlock()

	if existingBot, exists := shard.active[fingerprint]; exists {
		if existingBot.Addr == bot.Addr {
			shard.active[fingerprint] = bot
			return true
		}

		if ds.replaceOld {
			logger.Info("[DEDUP] Replacing old connection %s with new %s (fingerprint: %s)",
				existingBot.Addr, bot.Addr, fingerprint[:8])

			existingBot.Conn.Close()
			shard.active[fingerprint] = bot

			oldIP := extractIP(existingBot.Addr)
			ipShardOld := ds.getIPShard(oldIP)
			ipShardOld.mutex.Lock()
			delete(ipShardOld.ipToFingerprint, oldIP)
			ipShardOld.mutex.Unlock()

			newIP := extractIP(bot.Addr)
			ipShardNew := ds.getIPShard(newIP)
			ipShardNew.mutex.Lock()
			ipShardNew.ipToFingerprint[newIP] = fingerprint
			ipShardNew.mutex.Unlock()

			return true
		}

		ds.blockMutex.Lock()
		ds.totalBlocked++
		ds.blockMutex.Unlock()

		logger.Info("[DEDUP] DUPLICATE BLOCKED: %s (existing: %s, fingerprint: %s)",
			bot.Addr, existingBot.Addr, fingerprint[:8])
		return false
	}

	shard.active[fingerprint] = bot

	newIP := extractIP(bot.Addr)
	ipShardNew := ds.getIPShard(newIP)
	ipShardNew.mutex.Lock()
	ipShardNew.ipToFingerprint[newIP] = fingerprint
	ipShardNew.mutex.Unlock()

	logger.Info("[DEDUP] Registered new bot: %s (fingerprint: %s)", bot.Addr, fingerprint[:8])
	return true
}

func (ds *DeduplicationSystem) UnregisterBot(bot *Bot, fingerprint string) {
	if !ds.enabled {
		return
	}

	shard := ds.getDedupShard(fingerprint)
	shard.mutex.Lock()
	defer shard.mutex.Unlock()

	if existingBot, exists := shard.active[fingerprint]; exists {
		if existingBot.Addr == bot.Addr {
			delete(shard.active, fingerprint)

			ip := extractIP(bot.Addr)
			ipShard := ds.getIPShard(ip)
			ipShard.mutex.Lock()
			delete(ipShard.ipToFingerprint, ip)
			ipShard.mutex.Unlock()

			logger.Info("[DEDUP] Unregistered bot: %s (fingerprint: %s)", bot.Addr, fingerprint[:8])
		}
	}
}

