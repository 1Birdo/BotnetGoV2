package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

const (
	tokenLen    = 32
	sessTTL     = 30 * time.Minute
	jwtAlg      = "HS256"
	jwtIssuer   = "cnc-server"
	jwtAudience = "cnc-client"
	refreshLen  = 32
	refreshTTL  = 7 * 24 * time.Hour
	maxUserSess = 5
	denyGC      = 1 * time.Hour
)

var (
	secrets     *vault
	signKey     []byte
	refreshes   *smap
	blacklist   *denyList
	sessTbl     *smap
)

type vault struct {
	data map[string]string
	mu   sync.RWMutex
}

func newVault() *vault {
	return &vault{data: make(map[string]string)}
}

func (v *vault) Get(k string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	s, ok := v.data[k]
	return s, ok
}

func (v *vault) Set(k, val string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.data[k] = val
}

func (v *vault) Drop(k string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.data, k)
}

func (v *vault) LoadEnv(prefix string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, prefix) {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				v.data[strings.TrimPrefix(parts[0], prefix)] = parts[1]
			}
		}
	}
}

type denyList struct {
	revoked map[string]time.Time
	mu      sync.RWMutex
}

func newDenyList() *denyList {
	return &denyList{revoked: make(map[string]time.Time)}
}

func (d *denyList) Add(jti string, exp time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.revoked[jti] = exp
}

func (d *denyList) Has(jti string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.revoked[jti]
	return ok
}

func (d *denyList) gc() {
	t := time.NewTicker(denyGC)
	defer t.Stop()
	for range t.C {
		d.mu.Lock()
		now := time.Now()
		for jti, exp := range d.revoked {
			if now.After(exp) {
				delete(d.revoked, jti)
			}
		}
		d.mu.Unlock()
	}
}

func (d *denyList) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.revoked)
}

func initSessions() error {
	secrets = newVault()
	if err := loadJWTKey(); err != nil {
		return fmt.Errorf("jwt key: %w", err)
	}
	refreshes = makeSmap(maxSess)
	blacklist = newDenyList()
	sessTbl = makeSmap(maxSess)
	go sessGC()
	go blacklist.gc()
	return nil
}

func loadJWTKey() error {
	os.MkdirAll("data/certs", 0700)
	if k := os.Getenv("JWT_SIGNING_KEY"); k != "" {
		signKey = []byte(k)
		return nil
	}
	if k, err := os.ReadFile(jwtFile); err == nil {
		signKey = k
		return nil
	}
	signKey = make([]byte, 64)
	if _, err := rand.Read(signKey); err != nil {
		return err
	}
	return os.WriteFile(jwtFile, signKey, 0600)
}

func genToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func jti() (string, error) { return genToken(16) }

func startSess(user acct, ip, agent string) (*session, string, error) {
	if sessCount(user.Username) >= maxUserSess {
		evictSess(user.Username)
	}
	sid, err := genToken(tokenLen)
	if err != nil {
		return nil, "", err
	}
	refresh, err := genToken(refreshLen)
	if err != nil {
		return nil, "", err
	}
	id, err := jti()
	if err != nil {
		return nil, "", err
	}
	exp := time.Now().Add(sessTTL)
	tok, err := signToken(sid, user, id, exp)
	if err != nil {
		return nil, "", err
	}
	s := &session{
		ID: sid, User: user, IP: ip, Agent: agent,
		LoginAt: time.Now(), LastTouch: time.Now(), TTL: exp,
		Token: tok, Refresh: refresh, JTI: id,
	}
	if !sessTbl.Set(sid, s) {
		return nil, "", errors.New("too many sessions")
	}
	rd := map[string]interface{}{"session_id": sid, "expires_at": time.Now().Add(refreshTTL), "jwt_id": id}
	if !refreshes.Set(refresh, rd) {
		return nil, "", errors.New("refresh store full")
	}
	sessLog(user.Username, ip, "CREATED")
	return s, tok, nil
}

func signToken(sid string, u acct, id string, exp time.Time) (string, error) {
	c := claims{
		SessID: sid, UID: u.Username, Role: u.Level, JTI: id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    jwtIssuer,
			Audience:  jwt.ClaimStrings{jwtAudience},
			Subject:   u.Username,
			ID:        id,
		},
	}
	return jwt.NewWithClaims(jwt.GetSigningMethod(jwtAlg), c).SignedString(signKey)
}

func validSess(tok, ip, agent string) (*session, error) {
	cl, err := parseToken(tok)
	if err != nil {
		return nil, fmt.Errorf("bad token: %w", err)
	}
	if blacklist.Has(cl.JTI) {
		return nil, errors.New("revoked token")
	}
	raw, ok := sessTbl.Get(cl.SessID)
	if !ok {
		bcrypt.CompareHashAndPassword([]byte("$2a$10$x"), []byte("y"))
		return nil, errors.New("no session")
	}
	s := raw.(*session)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Revoked {
		return nil, errors.New("session revoked")
	}
	if time.Now().After(s.TTL) {
		removeSess(s.ID)
		return nil, errors.New("expired")
	}
	if s.Agent != "" && s.Agent != agent {
		sessLog(s.User.Username, ip, "AGENT_MISMATCH")
	}
	s.LastTouch = time.Now()
	sessTbl.Put(s.ID, s)
	return s, nil
}

func parseToken(raw string) (*claims, error) {
	t, err := jwt.ParseWithClaims(raw, &claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwtAlg {
			return nil, errors.New("wrong alg")
		}
		return signKey, nil
	})
	if err != nil {
		return nil, err
	}
	cl, ok := t.Claims.(*claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid claims")
	}
	if !cl.VerifyIssuer(jwtIssuer, true) || !cl.VerifyAudience(jwtAudience, true) {
		return nil, errors.New("bad issuer/audience")
	}
	return cl, nil
}

func renewSess(rTok, ip, agent string) (*session, string, error) {
	raw, ok := refreshes.Get(rTok)
	if !ok {
		return nil, "", errors.New("bad refresh token")
	}
	rd := raw.(map[string]interface{})
	sid := rd["session_id"].(string)
	exp := rd["expires_at"].(time.Time)
	oldJTI := rd["jwt_id"].(string)
	if time.Now().After(exp) {
		refreshes.Del(rTok)
		return nil, "", errors.New("refresh expired")
	}
	sRaw, ok := sessTbl.Get(sid)
	if !ok {
		refreshes.Del(rTok)
		return nil, "", errors.New("session gone")
	}
	s := sRaw.(*session)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Revoked {
		refreshes.Del(rTok)
		return nil, "", errors.New("revoked")
	}
	blacklist.Add(oldJTI, s.TTL)
	id, _ := jti()
	newExp := time.Now().Add(sessTTL)
	tok, err := signToken(s.ID, s.User, id, newExp)
	if err != nil {
		return nil, "", err
	}
	s.TTL = newExp
	s.LastTouch = time.Now()
	s.Token = tok
	s.JTI = id
	sessTbl.Put(s.ID, s)
	refreshes.Del(rTok)
	nr, _ := genToken(refreshLen)
	refreshes.Set(nr, map[string]interface{}{"session_id": sid, "expires_at": time.Now().Add(refreshTTL), "jwt_id": id})
	s.Refresh = nr
	sessLog(s.User.Username, ip, "REFRESHED")
	return s, tok, nil
}

func killSess(sid string) {
	raw, ok := sessTbl.Get(sid)
	if !ok {
		return
	}
	s := raw.(*session)
	s.mu.Lock()
	s.Revoked = true
	if s.JTI != "" {
		blacklist.Add(s.JTI, s.TTL)
	}
	s.mu.Unlock()
	refreshes.Del(s.Refresh)
	sessLog(s.User.Username, s.IP, "REVOKED")
}

func removeSess(sid string) {
	raw, ok := sessTbl.Get(sid)
	if !ok {
		return
	}
	s := raw.(*session)
	blacklist.Add(s.JTI, s.TTL)
	refreshes.Del(s.Refresh)
	sessTbl.Del(sid)
	sessLog(s.User.Username, s.IP, "REMOVED")
}

func killUserSess(username string) {
	sessTbl.Range(func(k string, v interface{}) bool {
		if v.(*session).User.Username == username {
			killSess(k)
		}
		return true
	})
}

func evictSess(username string) {
	var oldest *session
	sessTbl.Range(func(_ string, v interface{}) bool {
		s := v.(*session)
		if s.User.Username == username && !s.Revoked {
			if oldest == nil || s.LoginAt.Before(oldest.LoginAt) {
				oldest = s
			}
		}
		return true
	})
	if oldest != nil {
		killSess(oldest.ID)
	}
}

func sessCount(username string) int {
	n := 0
	sessTbl.Range(func(_ string, v interface{}) bool {
		s := v.(*session)
		if s.User.Username == username && !s.Revoked {
			n++
		}
		return true
	})
	return n
}

func sessGC() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		sessTbl.Range(func(k string, v interface{}) bool {
			s := v.(*session)
			if now.After(s.TTL) || s.Revoked {
				removeSess(k)
			}
			return true
		})
		refreshes.Range(func(k string, v interface{}) bool {
			rd := v.(map[string]interface{})
			if now.After(rd["expires_at"].(time.Time)) {
				refreshes.Del(k)
			}
			return true
		})
	}
}

func sessIdleGC() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		sessTbl.Range(func(k string, v interface{}) bool {
			s := v.(*session)
			if now.Sub(s.LastTouch) > sessDuration {
				sessLog(s.User.Username, s.IP, "EXPIRED")
				sessTbl.Del(k)
			}
			return true
		})
	}
}
