package main

import (
	"net"
	"regexp"
	"strconv"
	"time"
)

func validateIP(s string) bool {
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

func validatePort(s string) bool {
	p, err := strconv.Atoi(s)
	return err == nil && p > 0 && p <= 65535
}

func validateDuration(s string) (time.Duration, bool) {
	d, err := strconv.Atoi(s)
	if err != nil || d < 1 || d > 3600 {
		return 0, false
	}
	return time.Duration(d) * time.Second, true
}

func validateUser(u string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_-]{3,20}$`, u)
	return ok
}

func validatePass(p string) bool {
	if len(p) < 8 {
		return false
	}
	return regexp.MustCompile(`[A-Z]`).MatchString(p) &&
		regexp.MustCompile(`[a-z]`).MatchString(p) &&
		regexp.MustCompile(`[0-9]`).MatchString(p)
}

func validateFilename(f string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+\.tfx$`, f)
	return ok
}
