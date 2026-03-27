package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	loginLog     = sync.Map{}
	maxTries     = 3
	lockTime     = 5 * time.Minute
	sessDuration = 30 * time.Minute
	quotas       = sync.Map{}
	defQuota     = &qlimit{MaxConcurrent: 3, MaxDaily: 10, MaxDur: 300 * time.Second}
	connCt       = make(map[string]int)
	connMu       sync.Mutex
)

func tryLogin(user, pass string) (bool, *acct) {
	raw, err := os.ReadFile(userFile)
	if err != nil {
		secureEq("x", "y")
		return false, nil
	}
	var users []acct
	if json.Unmarshal(raw, &users) != nil {
		return false, nil
	}
	var hit *acct
	for i := range users {
		if timeSafeEq(users[i].Username, user) {
			hit = &users[i]
		}
	}
	if hit == nil {
		return false, nil
	}
	if !matchPass(hit.Password, pass) {
		return false, nil
	}
	if hit.Expire.Before(time.Now().UTC()) {
		return false, nil
	}
	return true, hit
}

func readUsers() ([]acct, error) {
	raw, err := os.ReadFile(userFile)
	if err != nil {
		return nil, err
	}
	var out []acct
	return out, json.Unmarshal(raw, &out)
}

func hashPass(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func matchPass(hashed, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(pw)) == nil
}

func hashKey(input string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := sha256.Sum256(append(salt, []byte(input)...))
	return fmt.Sprintf("%x:%x", salt, h), nil
}

func matchKey(hashed, plain string) bool { return matchPass(hashed, plain) }

func secureEq(a, b string) bool {
	ab, bb := []byte(a), []byte(b)
	if len(ab) != len(bb) {
		pad := make([]byte, max(len(ab), len(bb)))
		subtle.ConstantTimeCompare(ab, pad)
		subtle.ConstantTimeCompare(bb, pad)
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

func timeSafeEq(a, b string) bool { return secureEq(a, b) }

func randHex(n int) (string, error) {
	const abc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = abc[buf[i]%byte(len(abc))]
	}
	return string(buf), nil
}

func makeAPICreds() (string, string, error) {
	tok, err := randHex(16)
	if err != nil {
		return "", "", err
	}
	sec, err := randHex(24)
	if err != nil {
		return "", "", err
	}
	return tok, sec, nil
}

func canLogin(ip string) bool {
	raw, ok := loginLog.Load(ip)
	if !ok {
		loginLog.Store(ip, &loginRec{Count: 0, LastTry: time.Now()})
		return true
	}
	a := raw.(*loginRec)
	a.Lock.Lock()
	defer a.Lock.Unlock()
	if time.Since(a.LastTry) > lockTime {
		a.Count = 0
	}
	if a.Count >= maxTries {
		rateLog(ip, "auth lockout")
		return false
	}
	a.Count++
	a.LastTry = time.Now()
	return true
}

func clearLogin(ip string) { loginLog.Delete(ip) }

func grabConn(ip string) bool {
	connMu.Lock()
	defer connMu.Unlock()
	if connCt[ip] >= maxPerIP {
		return false
	}
	connCt[ip]++
	return true
}

func freeConn(ip string) {
	connMu.Lock()
	defer connMu.Unlock()
	if connCt[ip] > 0 {
		connCt[ip]--
	}
}

func sweepConns() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		connMu.Lock()
		for ip := range connCt {
			connCt[ip] = 0
		}
		connMu.Unlock()
	}
}

func getLimit(username string) *qlimit {
	raw, ok := quotas.Load(username)
	if ok {
		q := raw.(*qlimit)
		if time.Since(q.ResetAt) >= 24*time.Hour {
			q.UsedToday = 0
			q.ResetAt = time.Now()
		}
		return q
	}
	q := &qlimit{
		MaxConcurrent: defQuota.MaxConcurrent,
		MaxDaily:      defQuota.MaxDaily,
		MaxDur:        defQuota.MaxDur,
		ResetAt:       time.Now(),
	}
	quotas.Store(username, q)
	return q
}

func quotaOk(who string, dur time.Duration) (bool, string) {
	q := getLimit(who)
	live := 0
	runMu.Lock()
	for _, a := range running {
		if a.who == who && time.Now().Before(a.started.Add(a.dur)) {
			live++
		}
	}
	runMu.Unlock()
	if live >= q.MaxConcurrent {
		return false, "max concurrent attacks hit"
	}
	if q.UsedToday >= q.MaxDaily {
		return false, "daily limit reached"
	}
	if dur > q.MaxDur {
		return false, "duration too long"
	}
	q.UsedToday++
	quotas.Store(who, q)
	return true, ""
}

func sweepQuotas() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		quotas.Range(func(k, v interface{}) bool {
			q := v.(*qlimit)
			if time.Since(q.ResetAt) >= 24*time.Hour {
				q.UsedToday = 0
				q.ResetAt = time.Now()
			}
			return true
		})
	}
}

func sweepLogins() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		loginLog.Range(func(k, v interface{}) bool {
			a := v.(*loginRec)
			a.Lock.Lock()
			if time.Since(a.LastTry) > 24*time.Hour {
				loginLog.Delete(k)
			}
			a.Lock.Unlock()
			return true
		})
	}
}

func termTitle(t string) string            { return "\033]0;" + t + "\007" }
func pushTitle(c net.Conn, t string)       { c.Write([]byte(fmt.Sprintf("\033]0;%s\007", t))) }
