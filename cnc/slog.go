package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type logEntry struct {
	Stamp  time.Time   `json:"timestamp"`
	Level  string      `json:"level"`
	User   string      `json:"user,omitempty"`
	Action string      `json:"action"`
	Detail interface{} `json:"details,omitempty"`
	IP     string      `json:"ip,omitempty"`
}

type logHandle struct {
	sysFile *os.File
	perUser map[string]*os.File
	dir     string
	mu      sync.Mutex
}

var logger *logHandle

func initLog(dir string) error {
	logger = &logHandle{perUser: make(map[string]*os.File), dir: dir}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "system.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	logger.sysFile = f
	return nil
}

func (l *logHandle) emit(e logEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var f *os.File
	if e.Detail != nil && e.User != "" {
		if _, ok := l.perUser[e.User]; !ok {
			ud := filepath.Join(l.dir, "users")
			os.MkdirAll(ud, 0700)
			uf, err := os.OpenFile(filepath.Join(ud, e.User+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			l.perUser[e.User] = uf
		}
		f = l.perUser[e.User]
	} else {
		f = l.sysFile
	}
	e.Stamp = time.Now()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

func (l *logHandle) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for u, f := range l.perUser {
		f.Close()
		delete(l.perUser, u)
	}
	if l.sysFile != nil {
		return l.sysFile.Close()
	}
	return nil
}

func sysLog(level, action string, detail interface{}) {
	if logger == nil {
		return
	}
	logger.emit(logEntry{Level: level, Action: action, Detail: detail})
}

func userLog(level, user, action, ip string, detail interface{}) {
	if logger == nil {
		return
	}
	logger.emit(logEntry{Level: level, User: user, Action: action, Detail: detail, IP: ip})
}

func atkLog(user, method, target, port, dur, ip string) {
	userLog("INFO", user, "ATTACK", ip, map[string]string{
		"method": method, "target": target, "port": port, "duration": dur,
	})
}

func rateLog(ip, reason string) {
	sysLog("WARN", "RATE_LIMIT", map[string]string{"ip": ip, "reason": reason})
}

func quotaLog(user, kind string) {
	userLog("WARN", user, "QUOTA_HIT", "", map[string]string{"type": kind})
}

func sessLog(user, ip, action string) {
	userLog("INFO", user, "SESSION_"+action, ip, nil)
}

func validLog(ip, field, val string) {
	sysLog("WARN", "VALIDATION_FAIL", map[string]string{"ip": ip, "field": field, "value": val})
}

func authLog(user, ip string, ok bool) {
	lvl := "INFO"
	if !ok {
		lvl = "WARN"
	}
	userLog(lvl, user, "AUTH", ip, map[string]bool{"success": ok})
}

func botLog(ip string, connected bool) {
	act := "BOT_LEFT"
	if connected {
		act = "BOT_JOINED"
	}
	sysLog("INFO", act, map[string]string{"ip": ip})
}

func apiLog(user, endpoint, ip string, ok bool) {
	lvl := "INFO"
	if !ok {
		lvl = "WARN"
	}
	userLog(lvl, user, "API_REQ", ip, map[string]interface{}{"endpoint": endpoint, "ok": ok})
}

func fmtLog(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
