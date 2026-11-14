package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"overbyte-cnc/logger"
	"golang.org/x/crypto/hkdf"
)

const (
	KeyLen            = 16
	NonceLen          = 16
	TagLen            = 16
	KeyRotateInterval = 600
)

var masterKey []byte
var masterKeyInit sync.Once
var masterKeyErr error

func InitMasterKey() error {
	masterKeyInit.Do(func() {
		keyHex := strings.TrimSpace(strings.TrimPrefix(os.Getenv("OVERBYTE_CRYPTO_KEY"), "0x"))
		if keyHex == "" {
			masterKeyErr = fmt.Errorf("OVERBYTE_CRYPTO_KEY environment variable is required (32 hex chars = 16 bytes)")
			return
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil || len(key) != KeyLen {
			masterKeyErr = fmt.Errorf("OVERBYTE_CRYPTO_KEY must be 32 hex characters (16 bytes): %w", err)
			return
		}
		masterKey = key
	})
	return masterKeyErr
}

func getMasterKey() []byte {
	if len(masterKey) != KeyLen {
		panic("crypto: master key not initialized - call InitMasterKey() before use")
	}
	out := make([]byte, KeyLen)
	copy(out, masterKey)
	return out
}

var nonceCounter uint32

func init() {
	nonceCounter = uint32(time.Now().Unix() & 0xFFFFFFFF)
}

// ─── ASCON-128 core ───────────────────────────────────────────────────────────

type state struct {
	x0, x1, x2, x3, x4 uint64
}

func rotr64(x uint64, n int) uint64 {
	return (x >> n) | (x << (64 - n))
}

func load64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func store64(b []byte, x uint64) {
	b[0] = byte(x >> 56)
	b[1] = byte(x >> 48)
	b[2] = byte(x >> 40)
	b[3] = byte(x >> 32)
	b[4] = byte(x >> 24)
	b[5] = byte(x >> 16)
	b[6] = byte(x >> 8)
	b[7] = byte(x)
}

func (s *state) round(c byte) {
	s.x2 ^= uint64(c)

	s.x0 ^= s.x4
	s.x4 ^= s.x3
	s.x2 ^= s.x1

	t0 := s.x0 & (^s.x1)
	t1 := s.x1 & (^s.x2)
	t2 := s.x2 & (^s.x3)
	t3 := s.x3 & (^s.x4)
	t4 := s.x4 & (^s.x0)

	s.x0 ^= t1
	s.x1 ^= t2
	s.x2 ^= t3
	s.x3 ^= t4
	s.x4 ^= t0

	s.x1 ^= s.x0
	s.x0 ^= s.x4
	s.x3 ^= s.x2
	s.x2 = ^s.x2

	s.x0 ^= rotr64(s.x0, 19) ^ rotr64(s.x0, 28)
	s.x1 ^= rotr64(s.x1, 61) ^ rotr64(s.x1, 39)
	s.x2 ^= rotr64(s.x2, 1) ^ rotr64(s.x2, 6)
	s.x3 ^= rotr64(s.x3, 10) ^ rotr64(s.x3, 17)
	s.x4 ^= rotr64(s.x4, 7) ^ rotr64(s.x4, 41)
}

func (s *state) permutation(rounds int) {
	constants := []byte{0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}
	start := 12 - rounds
	for i := start; i < 12; i++ {
		s.round(constants[i])
	}
}

func (s *state) initialize(key, nonce []byte) {
	s.x0 = 0x80400c0600000000
	s.x1 = load64(key)
	s.x2 = load64(key[8:])
	s.x3 = load64(nonce)
	s.x4 = load64(nonce[8:])

	s.permutation(12)

	s.x3 ^= load64(key)
	s.x4 ^= load64(key[8:])
}

func (s *state) absorbAD(ad []byte) {
	if len(ad) == 0 {
		s.x4 ^= 1
		return
	}

	for len(ad) >= 8 {
		s.x0 ^= load64(ad)
		s.permutation(6)
		ad = ad[8:]
	}

	padded := make([]byte, 8)
	copy(padded, ad)
	padded[len(ad)] = 0x80
	s.x0 ^= load64(padded)
	s.permutation(6)

	s.x4 ^= 1
}

func (s *state) encrypt(plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	offset := 0

	for len(plaintext)-offset >= 8 {
		s.x0 ^= load64(plaintext[offset:])
		store64(ciphertext[offset:], s.x0)
		s.permutation(6)
		offset += 8
	}

	remaining := len(plaintext) - offset
	if remaining > 0 {
		padded := make([]byte, 8)
		copy(padded, plaintext[offset:])
		padded[remaining] = 0x80
		s.x0 ^= load64(padded)

		out := make([]byte, 8)
		store64(out, s.x0)
		copy(ciphertext[offset:], out[:remaining])
	}

	return ciphertext
}

func (s *state) decrypt(ciphertext []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	offset := 0

	for len(ciphertext)-offset >= 8 {
		cx := load64(ciphertext[offset:])
		store64(plaintext[offset:], s.x0^cx)
		s.x0 = cx
		s.permutation(6)
		offset += 8
	}

	remaining := len(ciphertext) - offset
	if remaining > 0 {
		out := make([]byte, 8)
		store64(out, s.x0)
		for i := 0; i < remaining; i++ {
			plaintext[offset+i] = out[i] ^ ciphertext[offset+i]
			out[i] = ciphertext[offset+i]
		}
		out[remaining] ^= 0x80
		s.x0 = load64(out)
	}

	return plaintext
}

func (s *state) finalize(key []byte) []byte {
	s.x1 ^= load64(key)
	s.x2 ^= load64(key[8:])

	s.permutation(12)

	s.x3 ^= load64(key)
	s.x4 ^= load64(key[8:])

	tag := make([]byte, TagLen)
	store64(tag, s.x3)
	store64(tag[8:], s.x4)
	return tag
}

func encodeEpoch(epoch uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(epoch >> 24)
	b[1] = byte(epoch >> 16)
	b[2] = byte(epoch >> 8)
	b[3] = byte(epoch)
	return b
}

const (
	sessionContext     = "CNC-BOT-SESSION-KEY-V2"
	ratchetInitContext = "CNC-BOT-RATCHET-INIT-V1"
)

func makeEpochInfo(context string, epoch uint32) []byte {
	eb := encodeEpoch(epoch)
	return append([]byte(context), eb...)
}

func hkdfDerive(salt, ikm, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	return out, nil
}

func deriveRatchetInit(master []byte, epoch uint32) ([]byte, error) {
	salt := encodeEpoch(epoch)
	info := makeEpochInfo(ratchetInitContext, epoch)
	return hkdfDerive(salt, master, info, KeyLen)
}

func deriveSessionKey(ratchetSt []byte, epoch uint32) ([]byte, error) {
	salt := encodeEpoch(epoch)
	info := makeEpochInfo(sessionContext, epoch)
	return hkdfDerive(salt, ratchetSt, info, KeyLen)
}

func getCurrentEpoch() uint32 {
	return uint32(time.Now().Unix() / KeyRotateInterval)
}

func getKeyForEpoch(epoch uint32) []byte {
	master := getMasterKey()
	rk, err := deriveRatchetInit(master, epoch)
	zeroize(master)
	if err != nil {
		return make([]byte, KeyLen)
	}
	sk, err := deriveSessionKey(rk, epoch)
	zeroize(rk)
	if err != nil {
		return make([]byte, KeyLen)
	}
	return sk
}

func GetActiveKey() []byte {
	return getKeyForEpoch(getCurrentEpoch())
}

func copyKey(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ─── Encrypt / Decrypt with epoch AD ─────────────────────────────────────────

func generateHybridNonce() ([]byte, error) {
	nonce := make([]byte, NonceLen)
	ctr := atomic.AddUint32(&nonceCounter, 1)
	binary.BigEndian.PutUint32(nonce[:4], ctr)
	if _, err := rand.Read(nonce[4:]); err != nil {
		return nil, err
	}
	return nonce, nil
}

func encryptWithEpoch(plaintext []byte, key []byte, epoch uint32) ([]byte, error) {
	nonce, err := generateHybridNonce()
	if err != nil {
		return nil, err
	}

	epochAD := encodeEpoch(epoch)

	s := &state{}
	s.initialize(key, nonce)
	s.absorbAD(epochAD)
	ciphertext := s.encrypt(plaintext)
	tag := s.finalize(key)

	frameLen := uint16(NonceLen + len(ciphertext) + TagLen)
	result := make([]byte, 2+int(frameLen))
	binary.BigEndian.PutUint16(result, frameLen)
	copy(result[2:], nonce)
	copy(result[2+NonceLen:], ciphertext)
	copy(result[2+NonceLen+len(ciphertext):], tag)

	return result, nil
}

func decryptWithEpoch(frame []byte, key []byte, epoch uint32) ([]byte, error) {
	if len(frame) < 2 {
		return nil, errors.New("frame too short")
	}

	frameLen := binary.BigEndian.Uint16(frame)
	if len(frame) < 2+int(frameLen) {
		return nil, errors.New("incomplete frame")
	}

	if frameLen < NonceLen+TagLen {
		return nil, errors.New("invalid frame length")
	}

	nonce := frame[2 : 2+NonceLen]
	ciphertextLen := int(frameLen) - NonceLen - TagLen
	ciphertext := frame[2+NonceLen : 2+NonceLen+ciphertextLen]
	tag := frame[2+NonceLen+ciphertextLen : 2+int(frameLen)]

	epochAD := encodeEpoch(epoch)

	s := &state{}
	s.initialize(key, nonce)
	s.absorbAD(epochAD)
	plaintext := s.decrypt(ciphertext)
	computedTag := s.finalize(key)

	diff := byte(0)
	for i := 0; i < TagLen; i++ {
		diff |= computedTag[i] ^ tag[i]
	}

	if diff != 0 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, errors.New("authentication failed")
	}

	return plaintext, nil
}

func Encrypt(plaintext []byte) ([]byte, error) {
	epoch := getCurrentEpoch()
	key := GetActiveKey()
	defer zeroize(key)
	return encryptWithEpoch(plaintext, key, epoch)
}

func Decrypt(frame []byte) ([]byte, error) {
	currentEpoch := getCurrentEpoch()

	epochs := []uint32{currentEpoch, currentEpoch - 1, currentEpoch + 1}
	for _, ep := range epochs {
		key := getKeyForEpoch(ep)
		plaintext, err := decryptWithEpoch(frame, key, ep)
		zeroize(key)
		if err == nil {
			return plaintext, nil
		}
	}

	logger.Warn("[CRYPTO] Decrypt failed: no valid epoch (CNC epoch=%d, tried %d,%d,%d)", currentEpoch, currentEpoch, currentEpoch-1, currentEpoch+1)
	return nil, errors.New("decryption failed - no valid epoch")
}

func SendEncrypted(conn net.Conn, data []byte) error {
	encrypted, err := Encrypt(data)
	if err != nil {
		return err
	}

	_, err = conn.Write(encrypted)
	return err
}

func RecvEncrypted(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	frameLen := binary.BigEndian.Uint16(header)
	if frameLen < NonceLen+TagLen || frameLen > 4096+NonceLen+TagLen {
		return nil, errors.New("invalid frame length")
	}

	frame := make([]byte, 2+int(frameLen))
	copy(frame, header)
	if _, err := io.ReadFull(conn, frame[2:]); err != nil {
		return nil, err
	}

	return Decrypt(frame)
}
