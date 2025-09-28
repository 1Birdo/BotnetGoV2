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

// Session Management Constants
const (
	SessionTokenLength    = 32
	DefaultSessionTimeout = 30 * time.Minute
	JWTSigningMethod      = "HS256"
	JWTIssuer             = "cnc-server"
	JWTAudience           = "cnc-client"
	RefreshTokenLength    = 32
	RefreshTokenTimeout   = 7 * 24 * time.Hour // 7 days
	MaxSessionsPerUser    = 5
	TokenBlacklistCleanup = 1 * time.Hour
)

type Session struct {
	ID           string    `json:"id"`
	User         User      `json:"user"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent,omitempty"`
	LoginTime    time.Time `json:"login_time"`
	LastActive   time.Time `json:"last_active"`
	ExpiresAt    time.Time `json:"expires_at"`
	Token        string    `json:"token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IsRevoked    bool      `json:"is_revoked"`
	JWTID        string    `json:"jwt_id"`
	mu           sync.Mutex
}

type JWTClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	UserLevel string `json:"user_level"`
	JWTID     string `json:"jti"`
	jwt.RegisteredClaims
}

type SecretManager struct {
	secrets map[string]string
	mu      sync.RWMutex
}

type TokenBlacklist struct {
	revokedTokens map[string]time.Time
	mu            sync.RWMutex
}

// Global variables
var (
	secretManager     *SecretManager
	jwtSigningKey     []byte
	refreshTokenStore *BoundedMap
	tokenBlacklist    *TokenBlacklist
)

func initSessionManagement() error {
	secretManager = NewSecretManager()
	if err := loadJWTSigningKey(); err != nil {
		return fmt.Errorf("failed to load JWT signing key: %w", err)
	}
	refreshTokenStore = NewBoundedMap(MaxSessions)
	tokenBlacklist = NewTokenBlacklist()
	go cleanupExpiredSessions()
	go tokenBlacklist.CleanupExpiredTokens()

	return nil
}

func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		revokedTokens: make(map[string]time.Time),
	}
}

func NewSecretManager() *SecretManager {
	return &SecretManager{
		secrets: make(map[string]string),
	}
}

func loadJWTSigningKey() error {
	if err := os.MkdirAll("data/certs", 0700); err != nil {
		return fmt.Errorf("creating certs directory: %w", err)
	}
	if key := os.Getenv("JWT_SIGNING_KEY"); key != "" {
		jwtSigningKey = []byte(key)
		return nil
	}

	if key, err := os.ReadFile("data/certs/jwt_signing.key"); err == nil {
		jwtSigningKey = key
		return nil
	}

	jwtSigningKey = make([]byte, 64) // 512 bits
	if _, err := rand.Read(jwtSigningKey); err != nil {
		return fmt.Errorf("failed to generate JWT signing key: %w", err)
	}

	if err := os.WriteFile("data/certs/jwt_signing.key", jwtSigningKey, 0600); err != nil {
		return fmt.Errorf("failed to save JWT signing key: %w", err)
	}

	return nil
}

func GenerateSecureToken(length int) (string, error) {
	tokenBytes := make([]byte, length)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

func GenerateJWTID() (string, error) {
	return GenerateSecureToken(16)
}

func (tb *TokenBlacklist) RevokeToken(jwtID string, expiresAt time.Time) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.revokedTokens[jwtID] = expiresAt
}

func (tb *TokenBlacklist) IsTokenRevoked(jwtID string) bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	_, exists := tb.revokedTokens[jwtID]
	return exists
}

func (tb *TokenBlacklist) CleanupExpiredTokens() {
	ticker := time.NewTicker(TokenBlacklistCleanup)
	defer ticker.Stop()

	for range ticker.C {
		tb.mu.Lock()
		now := time.Now()
		for jwtID, expiresAt := range tb.revokedTokens {
			if now.After(expiresAt) {
				delete(tb.revokedTokens, jwtID)
			}
		}
		tb.mu.Unlock()
	}
}

func (sm *SecretManager) GetSecret(key string) (string, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	secret, exists := sm.secrets[key]
	return secret, exists
}

func (sm *SecretManager) SetSecret(key, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.secrets[key] = value
}

func (sm *SecretManager) DeleteSecret(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.secrets, key)
}

func CreateSession(user User, ip, userAgent string) (*Session, string, error) {
	if count := CountUserSessions(user.Username); count >= MaxSessionsPerUser {
		RevokeOldestUserSession(user.Username)
	}

	sessionID, err := GenerateSecureToken(SessionTokenLength)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate session ID: %w", err)
	}

	refreshToken, err := GenerateSecureToken(RefreshTokenLength)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	jwtID, err := GenerateJWTID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate JWT ID: %w", err)
	}

	expiresAt := time.Now().Add(DefaultSessionTimeout)
	jwtToken, err := createJWTToken(sessionID, user, jwtID, expiresAt)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create JWT token: %w", err)
	}

	session := &Session{
		ID:           sessionID,
		User:         user,
		IP:           ip,
		UserAgent:    userAgent,
		LoginTime:    time.Now(),
		LastActive:   time.Now(),
		ExpiresAt:    expiresAt,
		Token:        jwtToken,
		RefreshToken: refreshToken,
		IsRevoked:    false,
		JWTID:        jwtID,
	}

	if !sessions.Set(sessionID, session) {
		return nil, "", errors.New("too many active sessions")
	}

	refreshTokenData := map[string]interface{}{
		"session_id": sessionID,
		"expires_at": time.Now().Add(RefreshTokenTimeout),
		"jwt_id":     jwtID,
	}
	if !refreshTokenStore.Set(refreshToken, refreshTokenData) {
		return nil, "", errors.New("failed to store refresh token")
	}

	LogSessionEvent(user.Username, ip, "CREATED")

	return session, jwtToken, nil
}

func createJWTToken(sessionID string, user User, jwtID string, expiresAt time.Time) (string, error) {
	claims := JWTClaims{
		SessionID: sessionID,
		UserID:    user.Username,
		UserLevel: user.Level,
		JWTID:     jwtID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    JWTIssuer,
			Audience:  jwt.ClaimStrings{JWTAudience},
			Subject:   user.Username,
			ID:        jwtID,
		},
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(JWTSigningMethod), claims)
	return token.SignedString(jwtSigningKey)
}

func ValidateSession(tokenString, ip, userAgent string) (*Session, error) {
	claims, err := parseAndValidateJWT(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if tokenBlacklist.IsTokenRevoked(claims.JWTID) {
		return nil, errors.New("token revoked")
	}

	sessionRaw, exists := sessions.Get(claims.SessionID)
	if !exists {
		bcrypt.CompareHashAndPassword([]byte("$2a$10$dummyHash"), []byte("dummyPassword"))
		return nil, errors.New("session not found")
	}

	session, ok := sessionRaw.(*Session)
	if !ok {
		LogSystem("ERROR", "INVALID_SESSION_TYPE", fmt.Sprintf("Expected *Session, got %T", sessionRaw))
		return nil, errors.New("session validation error")
	}
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.IsRevoked {
		return nil, errors.New("session revoked")
	}

	if time.Now().After(session.ExpiresAt) {
		RemoveSession(session.ID)
		return nil, errors.New("session expired")
	}

	if session.IP != ip {
		LogSessionEvent(session.User.Username, ip, "IP_MISMATCH")
		RevokeSession(session.ID)
		return nil, errors.New("IP address changed - session revoked")
	}

	if session.UserAgent != "" && session.UserAgent != userAgent {
		LogSessionEvent(session.User.Username, ip, "USER_AGENT_MISMATCH")
	}

	session.LastActive = time.Now()
	sessions.Store(session.ID, session)

	return session, nil
}

func parseAndValidateJWT(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != JWTSigningMethod {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSigningKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		if err := claims.Valid(); err != nil {
			return nil, fmt.Errorf("invalid claims: %w", err)
		}

		if !claims.VerifyIssuer(JWTIssuer, true) {
			return nil, errors.New("invalid issuer")
		}

		if !claims.VerifyAudience(JWTAudience, true) {
			return nil, errors.New("invalid audience")
		}

		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}

func RefreshSession(refreshToken, ip, userAgent string) (*Session, string, error) {
	refreshDataRaw, exists := refreshTokenStore.Get(refreshToken)
	if !exists {
		return nil, "", errors.New("invalid refresh token")
	}

	refreshData := refreshDataRaw.(map[string]interface{})
	sessionID := refreshData["session_id"].(string)
	expiresAt := refreshData["expires_at"].(time.Time)
	oldJWTID := refreshData["jwt_id"].(string)

	if time.Now().After(expiresAt) {
		refreshTokenStore.Delete(refreshToken)
		return nil, "", errors.New("refresh token expired")
	}

	sessionRaw, exists := sessions.Get(sessionID)
	if !exists {
		refreshTokenStore.Delete(refreshToken)
		return nil, "", errors.New("session not found")
	}

	session, ok := sessionRaw.(*Session)
	if !ok {
		LogSystem("ERROR", "INVALID_SESSION_TYPE", fmt.Sprintf("Expected *Session, got %T", sessionRaw))
		return nil, "", errors.New("session validation error")
	}
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.IsRevoked {
		refreshTokenStore.Delete(refreshToken)
		return nil, "", errors.New("session revoked")
	}

	tokenBlacklist.RevokeToken(oldJWTID, session.ExpiresAt)

	newJWTID, err := GenerateJWTID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate new JWT ID: %w", err)
	}

	newExpiresAt := time.Now().Add(DefaultSessionTimeout)
	newToken, err := createJWTToken(session.ID, session.User, newJWTID, newExpiresAt)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create new token: %w", err)
	}

	session.ExpiresAt = newExpiresAt
	session.LastActive = time.Now()
	session.Token = newToken
	session.JWTID = newJWTID
	sessions.Store(session.ID, session)

	refreshTokenStore.Delete(refreshToken)
	newRefreshToken, err := GenerateSecureToken(RefreshTokenLength)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	newRefreshData := map[string]interface{}{
		"session_id": sessionID,
		"expires_at": time.Now().Add(RefreshTokenTimeout),
		"jwt_id":     newJWTID,
	}
	if !refreshTokenStore.Set(newRefreshToken, newRefreshData) {
		return nil, "", errors.New("failed to store new refresh token")
	}

	session.RefreshToken = newRefreshToken

	LogSessionEvent(session.User.Username, ip, "REFRESHED")

	return session, newToken, nil
}

func RevokeSession(sessionID string) {
	sessionRaw, exists := sessions.Get(sessionID)
	if exists {
		session := sessionRaw.(*Session)
		session.mu.Lock()
		session.IsRevoked = true

		if session.JWTID != "" {
			tokenBlacklist.RevokeToken(session.JWTID, session.ExpiresAt)
		}

		session.mu.Unlock()

		refreshTokenStore.Delete(session.RefreshToken)

		LogSessionEvent(session.User.Username, session.IP, "REVOKED")
	}
}

func RevokeTokenByJWTID(jwtID string, expiresAt time.Time) {
	tokenBlacklist.RevokeToken(jwtID, expiresAt)
}

func RemoveSession(sessionID string) {
	if sessionRaw, exists := sessions.Get(sessionID); exists {
		session := sessionRaw.(*Session)

		tokenBlacklist.RevokeToken(session.JWTID, session.ExpiresAt)
		refreshTokenStore.Delete(session.RefreshToken)
		sessions.Delete(sessionID)

		LogSessionEvent(session.User.Username, session.IP, "REMOVED")
	}
}

func RevokeAllUserSessions(username string) {
	sessions.Range(func(key string, value interface{}) bool {
		session := value.(*Session)
		if session.User.Username == username {
			RevokeSession(session.ID)
		}
		return true
	})
}

func RevokeOldestUserSession(username string) {
	var oldestSession *Session
	var oldestTime time.Time

	sessions.Range(func(key string, value interface{}) bool {
		session := value.(*Session)
		if session.User.Username == username && !session.IsRevoked {
			if oldestSession == nil || session.LoginTime.Before(oldestTime) {
				oldestSession = session
				oldestTime = session.LoginTime
			}
		}
		return true
	})

	if oldestSession != nil {
		RevokeSession(oldestSession.ID)
	}
}

func CountUserSessions(username string) int {
	count := 0
	sessions.Range(func(key string, value interface{}) bool {
		session := value.(*Session)
		if session.User.Username == username && !session.IsRevoked {
			count++
		}
		return true
	})
	return count
}

func cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		sessions.Range(func(key string, value interface{}) bool {
			session := value.(*Session)
			if now.After(session.ExpiresAt) || session.IsRevoked {
				RemoveSession(key)
			}
			return true
		})

		refreshTokenStore.Range(func(key string, value interface{}) bool {
			refreshData := value.(map[string]interface{})
			expiresAt := refreshData["expires_at"].(time.Time)
			if now.After(expiresAt) {
				refreshTokenStore.Delete(key)
			}
			return true
		})
	}
}

func (sm *SecretManager) LoadSecretsFromEnv(prefix string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, env := range os.Environ() {
		if strings.HasPrefix(env, prefix) {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimPrefix(parts[0], prefix)
				sm.secrets[key] = parts[1] // Store encrypted in production
			}
		}
	}
}

func GenerateAPISecrets() (string, string, error) {
	token, err := GenerateSecureToken(16)
	if err != nil {
		return "", "", err
	}

	secret, err := GenerateSecureToken(24)
	if err != nil {
		return "", "", err
	}

	return token, secret, nil
}

func VerifyAPISecrets(userID, token, secret string) (bool, error) {
	users, err := loadUsers()
	if err != nil {
		return false, err
	}

	var user *User
	for _, u := range users {
		if u.Username == userID {
			user = &u
			break
		}
	}

	if user == nil {
		return false, errors.New("user not found")
	}

	if !SecureCompare(user.APIToken, token) {
		return false, nil
	}

	return VerifyAPISecret(user.APISecret, secret), nil
}

func GetTokenBlacklistSize() int {
	tokenBlacklist.mu.RLock()
	defer tokenBlacklist.mu.RUnlock()
	return len(tokenBlacklist.revokedTokens)
}

func IsJWTRevoked(jwtID string) bool {
	return tokenBlacklist.IsTokenRevoked(jwtID)
}

func ValidateSessionAndGetUser(tokenString, ip, userAgent string) (*Session, *User, error) {
	session, err := ValidateSession(tokenString, ip, userAgent)
	if err != nil {
		return nil, nil, err
	}
	return session, &session.User, nil
}
