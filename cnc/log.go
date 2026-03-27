package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type logLine struct {
	Stamp   time.Time   `json:"timestamp"`
	Level   string      `json:"level"`
	User    string      `json:"user,omitempty"`
	Action  string      `json:"action"`
	Detail  interface{} `json:"details,omitempty"`
	IP      string      `json:"ip,omitempty"`
}

type logWriter struct {
	sysFile  *os.File
	perUser  map[string]*os.File
	dir      string
	mu       sync.Mutex
}

var lg *logWriter

func setupLogger(dir string) error {
	lg = &logWriter{perUser: make(map[string]*os.File), dir: dir}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "system.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	lg.sysFile = f
	return nil
}

func (l *logWriter) write(e logLine) error {
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

func (l *logWriter) Close() error {
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

func logSys(level, action string, detail interface{}) {
	if lg == nil {
		return
	}
	lg.write(logLine{Level: level, Action: action, Detail: detail})
}

func logUsr(level, user, action, ip string, detail interface{}) {
	if lg == nil {
		return
	}
	lg.write(logLine{Level: level, User: user, Action: action, Detail: detail, IP: ip})
}

func logAttackEvt(user, method, target, port, dur, ip string) {
	logUsr("INFO", user, "ATTACK", ip, map[string]string{
		"method": method, "target": target, "port": port, "duration": dur,
	})
}

func logRateHit(ip, reason string) {
	logSys("WARN", "RATE_LIMIT", map[string]string{"ip": ip, "reason": reason})
}

func logQuotaHit(user, kind string) {
	logUsr("WARN", user, "QUOTA_HIT", "", map[string]string{"type": kind})
}

func logSessionEvt(user, ip, action string) {
	logUsr("INFO", user, "SESSION_"+action, ip, nil)
}

func logValidation(ip, field, val string) {
	logSys("WARN", "VALIDATION_FAIL", map[string]string{"ip": ip, "field": field, "value": val})
}

func logAuthEvt(user, ip string, ok bool) {
	lvl := "INFO"
	if !ok {
		lvl = "WARN"
	}
	logUsr(lvl, user, "AUTH", ip, map[string]bool{"success": ok})
}

func logBotConn(ip string, connected bool) {
	act := "BOT_LEFT"
	if connected {
		act = "BOT_JOINED"
	}
	logSys("INFO", act, map[string]string{"ip": ip})
}

func logAPIReq(user, endpoint, ip string, ok bool) {
	lvl := "INFO"
	if !ok {
		lvl = "WARN"
	}
	logUsr(lvl, user, "API_REQ", ip, map[string]interface{}{"endpoint": endpoint, "ok": ok})
}

func logf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
