package bot

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"overbyte-cnc/logger"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type BlockedIP struct {
	IP         string        `json:"ip"`
	AddedAt    time.Time     `json:"added_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
	Reason     string        `json:"reason"`
	RuleHandle uint64        `json:"-"`
}

type FirewallManager struct {
	conn        *nftables.Conn
	table       *nftables.Table
	chain       *nftables.Chain
	blockedIPs  map[string]*BlockedIP
	mutex       sync.RWMutex
	persistPath string
	botPort     uint16
	enabled     bool
	stopChan    chan struct{}
}

func NewFirewallManager(enabled bool, botPort int, persistPath string) (*FirewallManager, error) {
	fm := &FirewallManager{
		blockedIPs:  make(map[string]*BlockedIP),
		persistPath: persistPath,
		botPort:     uint16(botPort),
		enabled:     enabled,
		stopChan:    make(chan struct{}),
	}

	if !enabled {
		logger.Info("[FIREWALL] Disabled")
		return fm, nil
	}

	conn, err := nftables.New()
	if err != nil {
		logger.Info("[FIREWALL] Failed to connect to nftables: %v (requires root/CAP_NET_ADMIN)", err)
		fm.enabled = false
		return fm, nil
	}
	fm.conn = conn

	if err := fm.setupTable(); err != nil {
		logger.Info("[FIREWALL] Failed to setup table: %v", err)
		fm.enabled = false
		return fm, nil
	}

	if err := fm.LoadFromFile(); err != nil {
		logger.Info("[FIREWALL] Failed to load persisted blocklist: %v", err)
	}

	go fm.cleanupLoop()

	logger.Info("[FIREWALL] Initialized with nftables (port: %d)", botPort)
	return fm, nil
}

func (fm *FirewallManager) setupTable() error {
	fm.table = &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "cnc_filter",
	}
	fm.conn.AddTable(fm.table)

	fm.chain = &nftables.Chain{
		Name:     "blocklist",
		Table:    fm.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityRef(-100),
		Policy:   ptrChainPolicy(nftables.ChainPolicyAccept),
	}
	fm.conn.AddChain(fm.chain)

	if err := fm.conn.Flush(); err != nil {
		return err
	}

	logger.Info("[FIREWALL] Created table inet cnc_filter and chain blocklist")
	return nil
}

func ptrChainPolicy(p nftables.ChainPolicy) *nftables.ChainPolicy {
	return &p
}

func (fm *FirewallManager) BlockIP(ip string, reason string, duration time.Duration) error {
	if !fm.enabled || fm.conn == nil {
		return nil
	}

	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if _, exists := fm.blockedIPs[ip]; exists {
		return nil
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	ipv4 := parsedIP.To4()

	var rule *nftables.Rule
	if ipv4 != nil {
		rule = &nftables.Rule{
			Table: fm.table,
			Chain: fm.chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{byte(nftables.TableFamilyIPv4)},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ipv4,
				},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{6},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryPort(fm.botPort),
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		}
	} else {
		ipv6 := parsedIP.To16()
		rule = &nftables.Rule{
			Table: fm.table,
			Chain: fm.chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{byte(nftables.TableFamilyIPv6)},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       8,
					Len:          16,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ipv6,
				},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{6},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryPort(fm.botPort),
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		}
	}

	fm.conn.AddRule(rule)
	if err := fm.conn.Flush(); err != nil {
		logger.Info("[FIREWALL] Failed to block IP %s: %v", ip, err)
		return err
	}

	blocked := &BlockedIP{
		IP:        ip,
		AddedAt:   time.Now(),
		ExpiresAt: time.Now().Add(duration),
		Reason:    reason,
	}
	fm.blockedIPs[ip] = blocked

	fm.saveToFileNoLock()

	logger.Info("[FIREWALL] BLOCKED: %s (reason: %s, expires: %v)", ip, reason, duration)
	return nil
}

func (fm *FirewallManager) UnblockIP(ip string) error {
	if !fm.enabled || fm.conn == nil {
		return nil
	}

	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if _, exists := fm.blockedIPs[ip]; !exists {
		return nil
	}

	rules, err := fm.conn.GetRules(fm.table, fm.chain)
	if err != nil {
		return err
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	ipBytes := parsedIP.To4()
	if ipBytes == nil {
		ipBytes = parsedIP.To16()
	}

	for _, rule := range rules {
		if fm.ruleMatchesIP(rule, ipBytes) {
			if err := fm.conn.DelRule(rule); err != nil {
				logger.Info("[FIREWALL] Failed to delete rule for %s: %v", ip, err)
			}
		}
	}

	if err := fm.conn.Flush(); err != nil {
		return err
	}

	delete(fm.blockedIPs, ip)
	fm.saveToFileNoLock()

	logger.Info("[FIREWALL] UNBLOCKED: %s", ip)
	return nil
}

func (fm *FirewallManager) ruleMatchesIP(rule *nftables.Rule, ipBytes []byte) bool {
	for _, e := range rule.Exprs {
		if cmp, ok := e.(*expr.Cmp); ok {
			if len(cmp.Data) == len(ipBytes) {
				match := true
				for i := range cmp.Data {
					if cmp.Data[i] != ipBytes[i] {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
	}
	return false
}

func (fm *FirewallManager) LoadFromFile() error {
	if fm.persistPath == "" {
		return nil
	}

	file, err := os.Open(fm.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	scanner := bufio.NewScanner(file)
	now := time.Now()
	loaded := 0

	for scanner.Scan() {
		var entry BlockedIP
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		if now.After(entry.ExpiresAt) {
			continue
		}

		fm.mutex.Unlock()
		remaining := entry.ExpiresAt.Sub(now)
		fm.BlockIP(entry.IP, entry.Reason+" (restored)", remaining)
		fm.mutex.Lock()
			loaded++
		}

	logger.Info("[FIREWALL] Loaded %d blocked IPs from %s", loaded, fm.persistPath)
	return scanner.Err()
}

func (fm *FirewallManager) saveToFileNoLock() {
	if fm.persistPath == "" {
		return
	}

	file, err := os.Create(fm.persistPath)
	if err != nil {
		logger.Info("[FIREWALL] Failed to save blocklist: %v", err)
		return
	}
	defer file.Close()

	for _, entry := range fm.blockedIPs {
		data, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		file.Write(data)
		file.WriteString("\n")
	}
}

func (fm *FirewallManager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-fm.stopChan:
			return
		case <-ticker.C:
			fm.cleanupExpired()
		}
	}
}

func (fm *FirewallManager) cleanupExpired() {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	now := time.Now()
	var expired []string

	for ip, entry := range fm.blockedIPs {
		if now.After(entry.ExpiresAt) {
			expired = append(expired, ip)
		}
	}

	fm.mutex.Unlock()
	for _, ip := range expired {
		fm.UnblockIP(ip)
	}
	fm.mutex.Lock()

	if len(expired) > 0 {
		logger.Info("[FIREWALL] Cleaned up %d expired blocks", len(expired))
	}
}

func (fm *FirewallManager) Shutdown() {
	if !fm.enabled || fm.conn == nil {
		return
	}

	close(fm.stopChan)

	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	fm.conn.DelTable(fm.table)
	if err := fm.conn.Flush(); err != nil {
		logger.Info("[FIREWALL] Failed to cleanup table: %v", err)
	} else {
		logger.Info("[FIREWALL] Cleaned up nftables table")
	}
}

func binaryPort(port uint16) []byte {
	return []byte{byte(port >> 8), byte(port & 0xff)}
}

func (fm *FirewallManager) IsEnabled() bool {
	return fm.enabled
}
