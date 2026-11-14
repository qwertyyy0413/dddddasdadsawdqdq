package payload

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"overbyte-cnc/logger"
)

type TorBlocker struct {
	exitNodes map[string]bool
	mu        sync.RWMutex
	cacheTTL  time.Duration
	stopChan  chan struct{}
}

func NewTorBlocker(cacheTTL time.Duration) *TorBlocker {
	if cacheTTL < time.Minute {
		cacheTTL = time.Hour
	}
	return &TorBlocker{
		exitNodes: make(map[string]bool),
		cacheTTL:  cacheTTL,
		stopChan:  make(chan struct{}),
	}
}

func (tb *TorBlocker) Start() {
	tb.fetchExitNodes()

	go func() {
		ticker := time.NewTicker(tb.cacheTTL)
		defer ticker.Stop()
		for {
			select {
			case <-tb.stopChan:
				return
			case <-ticker.C:
				tb.fetchExitNodes()
			}
		}
	}()
}

func (tb *TorBlocker) Stop() {
	close(tb.stopChan)
}

func (tb *TorBlocker) IsTorExitNode(ip string) bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	return tb.exitNodes[ip]
}

func (tb *TorBlocker) fetchExitNodes() {
	urls := []string{
		"https://check.torproject.org/torbulkexitlist",
		"https://www.dan.me.uk/torlist/?exit",
	}

	for _, url := range urls {
		nodes, err := tb.fetchFromURL(url)
		if err != nil {
			logger.Warn("Failed to fetch Tor exit nodes from %s: %v", url, err)
			continue
		}

		if len(nodes) > 0 {
			tb.mu.Lock()
			tb.exitNodes = nodes
			tb.mu.Unlock()
			logger.Info("Loaded %d Tor exit node IPs from %s", len(nodes), url)
			return
		}
	}

	logger.Warn("Could not fetch Tor exit node list from any source")
}

func (tb *TorBlocker) fetchFromURL(url string) (map[string]bool, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	nodes := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			nodes[ip.String()] = true
		}
	}

	return nodes, scanner.Err()
}
