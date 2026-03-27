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
	loginTracker   = sync.Map{}
	maxLoginTries  = 3
	lockoutWindow  = 5 * time.Minute
	sessionTTL     = 30 * time.Minute
	userQuotas     = sync.Map{}
	defaultQuota   = &quota{MaxConcurrent: 3, MaxDaily: 10, MaxDur: 300 * time.Second}
	ipConnCount    = make(map[string]int)
	ipConnMu       sync.Mutex
)

func authenticate(user, pass string) (bool, *account) {
	raw, err := os.ReadFile(usersPath)
	if err != nil {
		safeCompare("x", "y")
		return false, nil
	}
	var users []account
	if json.Unmarshal(raw, &users) != nil {
		return false, nil
	}
	var hit *account
	for i := range users {
		if constEq(users[i].Username, user) {
			hit = &users[i]
		}
	}
	if hit == nil {
		return false, nil
	}
	if !checkHash(hit.Password, pass) {
		return false, nil
	}
	if hit.Expire.Before(time.Now().UTC()) {
		return false, nil
	}
	return true, hit
}

func loadUsers() ([]account, error) {
	raw, err := os.ReadFile(usersPath)
	if err != nil {
		return nil, err
	}
	var out []account
	return out, json.Unmarshal(raw, &out)
}

func hashPw(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func checkHash(hashed, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(pw)) == nil
}

func hashSecret(input string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := sha256.Sum256(append(salt, []byte(input)...))
	return fmt.Sprintf("%x:%x", salt, h), nil
}

func verifySecret(hashed, plain string) bool { return checkHash(hashed, plain) }

func safeCompare(a, b string) bool {
	ab, bb := []byte(a), []byte(b)
	if len(ab) != len(bb) {
		pad := make([]byte, max(len(ab), len(bb)))
		subtle.ConstantTimeCompare(ab, pad)
		subtle.ConstantTimeCompare(bb, pad)
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

func constEq(a, b string) bool { return safeCompare(a, b) }

func randStr(n int) (string, error) {
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

func genAPICreds() (string, string, error) {
	tok, err := randStr(16)
	if err != nil {
		return "", "", err
	}
	sec, err := randStr(24)
	if err != nil {
		return "", "", err
	}
	return tok, sec, nil
}

func checkLoginRate(ip string) bool {
	raw, ok := loginTracker.Load(ip)
	if !ok {
		loginTracker.Store(ip, &loginAttempt{Count: 0, LastTry: time.Now()})
		return true
	}
	a := raw.(*loginAttempt)
	a.Lock.Lock()
	defer a.Lock.Unlock()
	if time.Since(a.LastTry) > lockoutWindow {
		a.Count = 0
	}
	if a.Count >= maxLoginTries {
		logRateHit(ip, "auth lockout")
		return false
	}
	a.Count++
	a.LastTry = time.Now()
	return true
}

func resetLoginTracker(ip string) { loginTracker.Delete(ip) }

func checkConnLimit(ip string) bool {
	ipConnMu.Lock()
	defer ipConnMu.Unlock()
	if ipConnCount[ip] >= capPerIP {
		return false
	}
	ipConnCount[ip]++
	return true
}

func releaseConn(ip string) {
	ipConnMu.Lock()
	defer ipConnMu.Unlock()
	if ipConnCount[ip] > 0 {
		ipConnCount[ip]--
	}
}

func gcConnCounts() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		ipConnMu.Lock()
		for ip := range ipConnCount {
			ipConnCount[ip] = 0
		}
		ipConnMu.Unlock()
	}
}

func getQuota(username string) *quota {
	raw, ok := userQuotas.Load(username)
	if ok {
		q := raw.(*quota)
		if time.Since(q.ResetAt) >= 24*time.Hour {
			q.UsedToday = 0
			q.ResetAt = time.Now()
		}
		return q
	}
	q := &quota{
		MaxConcurrent: defaultQuota.MaxConcurrent,
		MaxDaily:      defaultQuota.MaxDaily,
		MaxDur:        defaultQuota.MaxDur,
		ResetAt:       time.Now(),
	}
	userQuotas.Store(username, q)
	return q
}

func canAttack(who string, dur time.Duration) (bool, string) {
	q := getQuota(who)
	live := 0
	atkMu.Lock()
	for _, a := range liveAttacks {
		if a.who == who && time.Now().Before(a.started.Add(a.dur)) {
			live++
		}
	}
	atkMu.Unlock()
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
	userQuotas.Store(who, q)
	return true, ""
}

func gcQuotas() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		userQuotas.Range(func(k, v interface{}) bool {
			q := v.(*quota)
			if time.Since(q.ResetAt) >= 24*time.Hour {
				q.UsedToday = 0
				q.ResetAt = time.Now()
			}
			return true
		})
	}
}

func gcLoginAttempts() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		loginTracker.Range(func(k, v interface{}) bool {
			a := v.(*loginAttempt)
			a.Lock.Lock()
			if time.Since(a.LastTry) > 24*time.Hour {
				loginTracker.Delete(k)
			}
			a.Lock.Unlock()
			return true
		})
	}
}

func (u *account) allowed(method string) bool {
	if u.Level == "Owner" {
		return true
	}
	aclMu.RLock()
	defer aclMu.RUnlock()
	roles, ok := permissions.Methods[method]
	if !ok {
		return false
	}
	for _, r := range roles {
		if u.Level == r {
			return true
		}
	}
	return false
}

func titleAnsi(t string) string            { return "\033]0;" + t + "\007" }
func setTermTitle(c net.Conn, t string)     { c.Write([]byte(fmt.Sprintf("\033]0;%s\007", t))) }
func rankFromStr(s string) rank {
	switch s {
	case "Owner": return rankOwner
	case "Admin": return rankAdmin
	case "Pro":   return rankPro
	default:      return rankBasic
	}
}
