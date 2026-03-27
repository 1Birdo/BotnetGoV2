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
	tokenLen      = 32
	sessTTL       = 30 * time.Minute
	jwtMethod     = "HS256"
	jwtIssuer     = "cnc-server"
	jwtAudience   = "cnc-client"
	refreshLen    = 32
	refreshTTL    = 7 * 24 * time.Hour
	maxUserSess   = 5
	blacklistGC   = 1 * time.Hour
)

var (
	vault        *secretStore
	jwtKey       []byte
	refreshTable *cmap
	denyList     *tokenDenyList
	sessions     *cmap
)

type secretStore struct {
	data map[string]string
	mu   sync.RWMutex
}

func newVault() *secretStore {
	return &secretStore{data: make(map[string]string)}
}

func (v *secretStore) Get(k string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	s, ok := v.data[k]
	return s, ok
}

func (v *secretStore) Set(k, val string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.data[k] = val
}

func (v *secretStore) Drop(k string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.data, k)
}

func (v *secretStore) LoadEnv(prefix string) {
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

type tokenDenyList struct {
	revoked map[string]time.Time
	mu      sync.RWMutex
}

func newDenyList() *tokenDenyList {
	return &tokenDenyList{revoked: make(map[string]time.Time)}
}

func (d *tokenDenyList) Add(jti string, exp time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.revoked[jti] = exp
}

func (d *tokenDenyList) Has(jti string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.revoked[jti]
	return ok
}

func (d *tokenDenyList) gc() {
	t := time.NewTicker(blacklistGC)
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

func (d *tokenDenyList) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.revoked)
}

func initTokens() error {
	vault = newVault()
	if err := loadSigningKey(); err != nil {
		return fmt.Errorf("jwt key: %w", err)
	}
	refreshTable = newCmap(capSessions)
	denyList = newDenyList()
	go gcExpiredSessions()
	go denyList.gc()
	return nil
}

func loadSigningKey() error {
	os.MkdirAll("data/certs", 0700)
	if k := os.Getenv("JWT_SIGNING_KEY"); k != "" {
		jwtKey = []byte(k)
		return nil
	}
	if k, err := os.ReadFile(jwtKeyFile); err == nil {
		jwtKey = k
		return nil
	}
	jwtKey = make([]byte, 64)
	if _, err := rand.Read(jwtKey); err != nil {
		return err
	}
	return os.WriteFile(jwtKeyFile, jwtKey, 0600)
}

func secureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func newJTI() (string, error) { return secureToken(16) }

func openSession(user account, ip, agent string) (*sess, string, error) {
	if countSessions(user.Username) >= maxUserSess {
		dropOldestSession(user.Username)
	}
	sid, err := secureToken(tokenLen)
	if err != nil {
		return nil, "", err
	}
	refresh, err := secureToken(refreshLen)
	if err != nil {
		return nil, "", err
	}
	jti, err := newJTI()
	if err != nil {
		return nil, "", err
	}
	exp := time.Now().Add(sessTTL)
	tok, err := signJWT(sid, user, jti, exp)
	if err != nil {
		return nil, "", err
	}
	s := &sess{
		ID: sid, User: user, IP: ip, Agent: agent,
		LoginAt: time.Now(), LastTouch: time.Now(), TTL: exp,
		Token: tok, Refresh: refresh, JTI: jti,
	}
	if !sessions.Set(sid, s) {
		return nil, "", errors.New("too many sessions")
	}
	rd := map[string]interface{}{"session_id": sid, "expires_at": time.Now().Add(refreshTTL), "jwt_id": jti}
	if !refreshTable.Set(refresh, rd) {
		return nil, "", errors.New("refresh store full")
	}
	logSessionEvt(user.Username, ip, "CREATED")
	return s, tok, nil
}

func signJWT(sid string, u account, jti string, exp time.Time) (string, error) {
	c := jwtClaims{
		SessID: sid, UID: u.Username, Role: u.Level, JTI: jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    jwtIssuer,
			Audience:  jwt.ClaimStrings{jwtAudience},
			Subject:   u.Username,
			ID:        jti,
		},
	}
	return jwt.NewWithClaims(jwt.GetSigningMethod(jwtMethod), c).SignedString(jwtKey)
}

func checkSession(tok, ip, agent string) (*sess, error) {
	cl, err := parseJWT(tok)
	if err != nil {
		return nil, fmt.Errorf("bad token: %w", err)
	}
	if denyList.Has(cl.JTI) {
		return nil, errors.New("revoked token")
	}
	raw, ok := sessions.Get(cl.SessID)
	if !ok {
		bcrypt.CompareHashAndPassword([]byte("$2a$10$x"), []byte("y"))
		return nil, errors.New("no session")
	}
	s := raw.(*sess)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Revoked {
		return nil, errors.New("session revoked")
	}
	if time.Now().After(s.TTL) {
		dropSession(s.ID)
		return nil, errors.New("expired")
	}
	if s.Agent != "" && s.Agent != agent {
		logSessionEvt(s.User.Username, ip, "AGENT_MISMATCH")
	}
	s.LastTouch = time.Now()
	sessions.Put(s.ID, s)
	return s, nil
}

func parseJWT(raw string) (*jwtClaims, error) {
	t, err := jwt.ParseWithClaims(raw, &jwtClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwtMethod {
			return nil, errors.New("wrong alg")
		}
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	cl, ok := t.Claims.(*jwtClaims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid claims")
	}
	if !cl.VerifyIssuer(jwtIssuer, true) || !cl.VerifyAudience(jwtAudience, true) {
		return nil, errors.New("bad issuer/audience")
	}
	return cl, nil
}

func refreshSession(rTok, ip, agent string) (*sess, string, error) {
	raw, ok := refreshTable.Get(rTok)
	if !ok {
		return nil, "", errors.New("bad refresh token")
	}
	rd := raw.(map[string]interface{})
	sid := rd["session_id"].(string)
	exp := rd["expires_at"].(time.Time)
	oldJTI := rd["jwt_id"].(string)
	if time.Now().After(exp) {
		refreshTable.Del(rTok)
		return nil, "", errors.New("refresh expired")
	}
	sRaw, ok := sessions.Get(sid)
	if !ok {
		refreshTable.Del(rTok)
		return nil, "", errors.New("session gone")
	}
	s := sRaw.(*sess)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Revoked {
		refreshTable.Del(rTok)
		return nil, "", errors.New("revoked")
	}
	denyList.Add(oldJTI, s.TTL)
	jti, _ := newJTI()
	newExp := time.Now().Add(sessTTL)
	tok, err := signJWT(s.ID, s.User, jti, newExp)
	if err != nil {
		return nil, "", err
	}
	s.TTL = newExp
	s.LastTouch = time.Now()
	s.Token = tok
	s.JTI = jti
	sessions.Put(s.ID, s)
	refreshTable.Del(rTok)
	nr, _ := secureToken(refreshLen)
	refreshTable.Set(nr, map[string]interface{}{"session_id": sid, "expires_at": time.Now().Add(refreshTTL), "jwt_id": jti})
	s.Refresh = nr
	logSessionEvt(s.User.Username, ip, "REFRESHED")
	return s, tok, nil
}

func revokeSession(sid string) {
	raw, ok := sessions.Get(sid)
	if !ok {
		return
	}
	s := raw.(*sess)
	s.mu.Lock()
	s.Revoked = true
	if s.JTI != "" {
		denyList.Add(s.JTI, s.TTL)
	}
	s.mu.Unlock()
	refreshTable.Del(s.Refresh)
	logSessionEvt(s.User.Username, s.IP, "REVOKED")
}

func dropSession(sid string) {
	raw, ok := sessions.Get(sid)
	if !ok {
		return
	}
	s := raw.(*sess)
	denyList.Add(s.JTI, s.TTL)
	refreshTable.Del(s.Refresh)
	sessions.Del(sid)
	logSessionEvt(s.User.Username, s.IP, "REMOVED")
}

func revokeUserSessions(username string) {
	sessions.Each(func(k string, v interface{}) bool {
		if v.(*sess).User.Username == username {
			revokeSession(k)
		}
		return true
	})
}

func dropOldestSession(username string) {
	var oldest *sess
	sessions.Each(func(_ string, v interface{}) bool {
		s := v.(*sess)
		if s.User.Username == username && !s.Revoked {
			if oldest == nil || s.LoginAt.Before(oldest.LoginAt) {
				oldest = s
			}
		}
		return true
	})
	if oldest != nil {
		revokeSession(oldest.ID)
	}
}

func countSessions(username string) int {
	n := 0
	sessions.Each(func(_ string, v interface{}) bool {
		s := v.(*sess)
		if s.User.Username == username && !s.Revoked {
			n++
		}
		return true
	})
	return n
}

func gcExpiredSessions() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		sessions.Each(func(k string, v interface{}) bool {
			s := v.(*sess)
			if now.After(s.TTL) || s.Revoked {
				dropSession(k)
			}
			return true
		})
		refreshTable.Each(func(k string, v interface{}) bool {
			rd := v.(map[string]interface{})
			if now.After(rd["expires_at"].(time.Time)) {
				refreshTable.Del(k)
			}
			return true
		})
	}
}

func gcSessions() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		sessions.Each(func(k string, v interface{}) bool {
			s := v.(*sess)
			if now.Sub(s.LastTouch) > sessionTTL {
				logSessionEvt(s.User.Username, s.IP, "EXPIRED")
				sessions.Del(k)
			}
			return true
		})
	}
}
