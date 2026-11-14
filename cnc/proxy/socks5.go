package proxy

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"overbyte-cnc/logger"
)

const (
	SOCKS5_VERSION          = 0x05
	SOCKS5_AUTH_NONE        = 0x00
	SOCKS5_AUTH_PASSWORD    = 0x02
	SOCKS5_AUTH_NO_ACCEPT   = 0xFF
	SOCKS5_CMD_CONNECT      = 0x01
	SOCKS5_ATYP_IPV4        = 0x01
	SOCKS5_ATYP_DOMAIN      = 0x03
	SOCKS5_ATYP_IPV6        = 0x04
	SOCKS5_REP_SUCCESS      = 0x00
	SOCKS5_REP_HOST_UNREACH = 0x04
	SOCKS5_REP_CMD_UNSUPP   = 0x07
	SOCKS5_REP_ADDR_UNSUPP  = 0x08
)

type SOCKS5Server struct {
	listener     net.Listener
	bindAddr     string
	targetAddr   string
	authEnabled  bool
	authUsername string
	authPassword string
	running      bool
	mutex        sync.Mutex
}

type SOCKS5Config struct {
	Enabled      bool
	BindAddr     string
	BindPort     int
	TargetPort   int
	AuthEnabled  bool
	AuthUsername string
	AuthPassword string
}

func NewSOCKS5Server(cfg SOCKS5Config) *SOCKS5Server {
	return &SOCKS5Server{
		bindAddr:     fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.BindPort),
		targetAddr:   fmt.Sprintf("127.0.0.1:%d", cfg.TargetPort),
		authEnabled:  cfg.AuthEnabled,
		authUsername: cfg.AuthUsername,
		authPassword: cfg.AuthPassword,
	}
}

func (s *SOCKS5Server) Start() error {
	listener, err := net.Listen("tcp", s.bindAddr)
	if err != nil {
		return err
	}
	s.listener = listener
	s.running = true

	logger.Info("SOCKS5 proxy listening on %s", s.bindAddr)

	go s.acceptLoop()
	return nil
}

func (s *SOCKS5Server) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *SOCKS5Server) acceptLoop() {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				logger.Error("SOCKS5 accept error: %v", err)
			}
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("SOCKS5 panic: %v", r)
		}
	}()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := s.handleHandshake(conn); err != nil {
		logger.Debug("SOCKS5 handshake failed: %v", err)
		conn.Close()
		return
	}

	targetConn, err := s.handleRequest(conn)
	if err != nil {
		logger.Debug("SOCKS5 request failed: %v", err)
		conn.Close()
		return
	}

	conn.SetDeadline(time.Time{})

	s.relay(conn, targetConn)
}

func (s *SOCKS5Server) handleHandshake(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != SOCKS5_VERSION {
		return errors.New("invalid SOCKS version")
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	var selectedMethod byte = SOCKS5_AUTH_NO_ACCEPT

	if s.authEnabled {
		for _, m := range methods {
			if m == SOCKS5_AUTH_PASSWORD {
				selectedMethod = SOCKS5_AUTH_PASSWORD
				break
			}
		}
	} else {
		for _, m := range methods {
			if m == SOCKS5_AUTH_NONE {
				selectedMethod = SOCKS5_AUTH_NONE
				break
			}
		}
	}

	conn.Write([]byte{SOCKS5_VERSION, selectedMethod})

	if selectedMethod == SOCKS5_AUTH_NO_ACCEPT {
		return errors.New("no acceptable auth method")
	}

	if selectedMethod == SOCKS5_AUTH_PASSWORD {
		if err := s.handleAuth(conn); err != nil {
			return err
		}
	}

	return nil
}

func (s *SOCKS5Server) handleAuth(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		return errors.New("invalid auth version")
	}

	usernameLen := int(header[1])
	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return err
	}

	passwordLen := int(passLenBuf[0])
	password := make([]byte, passwordLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	usernameMatch := subtle.ConstantTimeCompare(username, []byte(s.authUsername)) == 1
	passwordMatch := subtle.ConstantTimeCompare(password, []byte(s.authPassword)) == 1

	if usernameMatch && passwordMatch {
		conn.Write([]byte{0x01, 0x00})
		return nil
	}

	conn.Write([]byte{0x01, 0x01})
	return errors.New("authentication failed")
}

func (s *SOCKS5Server) handleRequest(conn net.Conn) (net.Conn, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != SOCKS5_VERSION {
		return nil, errors.New("invalid SOCKS version")
	}

	if header[1] != SOCKS5_CMD_CONNECT {
		s.sendReply(conn, SOCKS5_REP_CMD_UNSUPP)
		return nil, errors.New("unsupported command")
	}

	var destAddr string
	switch header[3] {
	case SOCKS5_ATYP_IPV4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		destAddr = net.IP(addr).String()
	case SOCKS5_ATYP_DOMAIN:
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return nil, err
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		destAddr = string(domain)
	case SOCKS5_ATYP_IPV6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		destAddr = net.IP(addr).String()
	default:
		s.sendReply(conn, SOCKS5_REP_ADDR_UNSUPP)
		return nil, errors.New("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	_ = binary.BigEndian.Uint16(portBuf)
	_ = destAddr

	targetConn, err := net.DialTimeout("tcp", s.targetAddr, 10*time.Second)
	if err != nil {
		s.sendReply(conn, SOCKS5_REP_HOST_UNREACH)
		return nil, err
	}

	s.sendReply(conn, SOCKS5_REP_SUCCESS)

	return targetConn, nil
}

func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte) {
	reply := []byte{
		SOCKS5_VERSION,
		rep,
		0x00,
		SOCKS5_ATYP_IPV4,
		0, 0, 0, 0,
		0, 0,
	}
	conn.Write(reply)
}

func (s *SOCKS5Server) relay(client, target net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(target, client)
		if tcp, ok := target.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		io.Copy(client, target)
		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done

	client.Close()
	target.Close()
}
