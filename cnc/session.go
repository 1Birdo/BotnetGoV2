package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
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

// Session represents a user session with enhanced security features
type Session struct {
	ID           string    `json:"id"`
	User         User      `json:"user"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent,omitempty"`
	LoginTime    time.Time `json:"login_time"`
	LastActive   time.Time `json:"last_active"`
	ExpiresAt    time.Time `json:"expires_at"`
	Token        string    `json:"token,omitempty"` // JWT token
	RefreshToken string    `json:"refresh_token,omitempty"`
	IsRevoked    bool      `json:"is_revoked"`
	JWTID        string    `json:"jwt_id"` // Unique JWT identifier for revocation
	mu           sync.Mutex
}

// JWTClaims represents custom claims for JWT tokens
type JWTClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	UserLevel string `json:"user_level"`
	JWTID     string `json:"jti"` // JWT ID for revocation
	jwt.RegisteredClaims
}

// SecretManager handles secure storage and retrieval of secrets
type SecretManager struct {
	secrets map[string]string
	mu      sync.RWMutex
}

// TokenBlacklist manages revoked tokens before their expiration
type TokenBlacklist struct {
	revokedTokens map[string]time.Time // token ID -> expiration time
	mu            sync.RWMutex
}

// Global variables
var (
	secretManager     *SecretManager
	jwtSigningKey     []byte
	refreshTokenStore *BoundedMap // Stores refresh tokens with session ID as key
	tokenBlacklist    *TokenBlacklist
)

// Initialize session management system
func initSessionManagement() error {
	// Initialize secret manager
	secretManager = NewSecretManager()
	// Load or generate JWT signing key
	if err := loadJWTSigningKey(); err != nil {
		return fmt.Errorf("failed to load JWT signing key: %w", err)
	}

	// Initialize refresh token store
	refreshTokenStore = NewBoundedMap(MaxSessions)

	// Initialize token blacklist
	tokenBlacklist = NewTokenBlacklist()

	// Start session cleanup routine
	go cleanupExpiredSessions()

	// Start token blacklist cleanup routine
	go tokenBlacklist.CleanupExpiredTokens()

	return nil
}

// NewTokenBlacklist creates a new token blacklist instance
func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		revokedTokens: make(map[string]time.Time),
	}
}

// NewSecretManager creates a new secret manager instance
func NewSecretManager() *SecretManager {
	return &SecretManager{
		secrets: make(map[string]string),
	}
}

// loadJWTSigningKey loads or generates the JWT signing key
func loadJWTSigningKey() error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll("data/certs", 0700); err != nil {
		return fmt.Errorf("creating certs directory: %w", err)
	}
	// Try to load from environment variable first
	if key := os.Getenv("JWT_SIGNING_KEY"); key != "" {
		jwtSigningKey = []byte(key)
		return nil
	}

	// Try to load from secure file
	if key, err := os.ReadFile("data/certs/jwt_signing.key"); err == nil {
		jwtSigningKey = key
		return nil
	}

	// Generate a new key
	jwtSigningKey = make([]byte, 64) // 512 bits
	if _, err := rand.Read(jwtSigningKey); err != nil {
		return fmt.Errorf("failed to generate JWT signing key: %w", err)
	}

	// Save the key to a file (in production, use a proper secret management system)
	if err := os.WriteFile("data/certs/jwt_signing.key", jwtSigningKey, 0600); err != nil {
		return fmt.Errorf("failed to save JWT signing key: %w", err)
	}

	return nil
}

// GenerateSecureToken creates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	tokenBytes := make([]byte, length)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

// GenerateJWTID generates a unique JWT ID
func GenerateJWTID() (string, error) {
	return GenerateSecureToken(16)
}

// RevokeToken adds a token to the blacklist
func (tb *TokenBlacklist) RevokeToken(jwtID string, expiresAt time.Time) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.revokedTokens[jwtID] = expiresAt
}

// IsTokenRevoked checks if a token is in the blacklist
func (tb *TokenBlacklist) IsTokenRevoked(jwtID string) bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	_, exists := tb.revokedTokens[jwtID]
	return exists
}

// CleanupExpiredTokens removes expired tokens from the blacklist
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

// GetSecret retrieves a secret from the secret manager
func (sm *SecretManager) GetSecret(key string) (string, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	secret, exists := sm.secrets[key]
	return secret, exists
}

// SetSecret stores a secret in the secret manager
func (sm *SecretManager) SetSecret(key, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.secrets[key] = value
}

// DeleteSecret removes a secret
func (sm *SecretManager) DeleteSecret(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.secrets, key)
}

// CreateSession creates a new session with enhanced security features
func CreateSession(user User, ip, userAgent string) (*Session, string, error) {
	// Check if user has too many active sessions
	if count := CountUserSessions(user.Username); count >= MaxSessionsPerUser {
		// Revoke oldest session
		RevokeOldestUserSession(user.Username)
	}

	// Generate session ID
	sessionID, err := GenerateSecureToken(SessionTokenLength)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Generate refresh token
	refreshToken, err := GenerateSecureToken(RefreshTokenLength)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Generate unique JWT ID for revocation
	jwtID, err := GenerateJWTID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate JWT ID: %w", err)
	}

	// Create JWT token
	expiresAt := time.Now().Add(DefaultSessionTimeout)
	jwtToken, err := createJWTToken(sessionID, user, jwtID, expiresAt)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create JWT token: %w", err)
	}

	// Create session object
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

	// Store session
	if !sessions.Set(sessionID, session) {
		return nil, "", errors.New("too many active sessions")
	}

	// Store refresh token
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

// createJWTToken creates a JWT token with custom claims
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

// ValidateSession validates a session token and returns the session
func ValidateSession(tokenString, ip, userAgent string) (*Session, error) {
	// Parse and validate JWT token with full claims validation
	claims, err := parseAndValidateJWT(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Check if token has been revoked
	if tokenBlacklist.IsTokenRevoked(claims.JWTID) {
		return nil, errors.New("token revoked")
	}

	// Retrieve session
	sessionRaw, exists := sessions.Get(claims.SessionID)
	if !exists {
		// Perform dummy operation to prevent timing attacks
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

	// Check if session is revoked
	if session.IsRevoked {
		return nil, errors.New("session revoked")
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		RemoveSession(session.ID)
		return nil, errors.New("session expired")
	}

	// Verify IP address (allow same subnet)
	if session.IP != ip { // Replace the isSameSubnet call
		LogSessionEvent(session.User.Username, ip, "IP_MISMATCH")
		RevokeSession(session.ID)
		return nil, errors.New("IP address changed - session revoked")
	}

	// Verify user agent (optional but recommended)
	if session.UserAgent != "" && session.UserAgent != userAgent {
		LogSessionEvent(session.User.Username, ip, "USER_AGENT_MISMATCH")
		// Don't revoke immediately, just log for investigation
	}

	// Update last active time
	session.LastActive = time.Now()
	sessions.Store(session.ID, session)

	return session, nil
}

// parseAndValidateJWT parses and validates a JWT token with full claims validation
func parseAndValidateJWT(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if token.Method.Alg() != JWTSigningMethod {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSigningKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		// Validate all standard claims
		if err := claims.Valid(); err != nil {
			return nil, fmt.Errorf("invalid claims: %w", err)
		}

		// Custom validation for issuer
		if !claims.VerifyIssuer(JWTIssuer, true) {
			return nil, errors.New("invalid issuer")
		}

		// Custom validation for audience
		if !claims.VerifyAudience(JWTAudience, true) {
			return nil, errors.New("invalid audience")
		}

		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}

// RefreshSession refreshes an expired session using a refresh token
func RefreshSession(refreshToken, ip, userAgent string) (*Session, string, error) {
	// Retrieve refresh token data
	refreshDataRaw, exists := refreshTokenStore.Get(refreshToken)
	if !exists {
		return nil, "", errors.New("invalid refresh token")
	}

	refreshData := refreshDataRaw.(map[string]interface{})
	sessionID := refreshData["session_id"].(string)
	expiresAt := refreshData["expires_at"].(time.Time)
	oldJWTID := refreshData["jwt_id"].(string)

	// Check if refresh token has expired
	if time.Now().After(expiresAt) {
		refreshTokenStore.Delete(refreshToken)
		return nil, "", errors.New("refresh token expired")
	}

	// Retrieve session
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

	// Check if session is revoked
	if session.IsRevoked {
		refreshTokenStore.Delete(refreshToken)
		return nil, "", errors.New("session revoked")
	}

	// Revoke the old JWT token
	tokenBlacklist.RevokeToken(oldJWTID, session.ExpiresAt)

	// Generate new JWT ID
	newJWTID, err := GenerateJWTID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate new JWT ID: %w", err)
	}

	// Create new JWT token
	newExpiresAt := time.Now().Add(DefaultSessionTimeout)
	newToken, err := createJWTToken(session.ID, session.User, newJWTID, newExpiresAt)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create new token: %w", err)
	}

	// Update session
	session.ExpiresAt = newExpiresAt
	session.LastActive = time.Now()
	session.Token = newToken
	session.JWTID = newJWTID
	sessions.Store(session.ID, session)

	// Invalidate old refresh token and generate a new one
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

// RevokeSession revokes a session immediately and blacklists the token
func RevokeSession(sessionID string) {
	sessionRaw, exists := sessions.Get(sessionID)
	if exists {
		session := sessionRaw.(*Session)
		session.mu.Lock()
		session.IsRevoked = true

		// Add the JWT token to blacklist
		if session.JWTID != "" {
			tokenBlacklist.RevokeToken(session.JWTID, session.ExpiresAt)
		}

		session.mu.Unlock()

		// Remove refresh token
		refreshTokenStore.Delete(session.RefreshToken)

		LogSessionEvent(session.User.Username, session.IP, "REVOKED")
	}
}

// RevokeTokenByJWTID revokes a specific JWT token by its ID
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

// RevokeAllUserSessions revokes all sessions for a specific user
func RevokeAllUserSessions(username string) {
	sessions.Range(func(key string, value interface{}) bool {
		session := value.(*Session)
		if session.User.Username == username {
			RevokeSession(session.ID)
		}
		return true
	})
}

// RevokeOldestUserSession revokes the oldest session for a user
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

// CountUserSessions counts active sessions for a user
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

// cleanupExpiredSessions periodically cleans up expired sessions
func cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		// Clean up expired sessions
		sessions.Range(func(key string, value interface{}) bool {
			session := value.(*Session)
			if now.After(session.ExpiresAt) || session.IsRevoked {
				RemoveSession(key)
			}
			return true
		})

		// Clean up expired refresh tokens
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

// LoadSecretsFromEnv loads secrets from environment variables
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

// GenerateAPISecrets generates secure API token and secret pairs
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

// VerifyAPISecrets verifies API token and secret
func VerifyAPISecrets(userID, token, secret string) (bool, error) {
	users, err := loadUsers()
	if err != nil {
		return false, err
	}

	// Find the user
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

// Helper function to check if two IPs are in the same subnet
func isSameSubnet(ip1, ip2 net.IP, maskBits int) bool {
	if ip1 == nil || ip2 == nil {
		return false
	}

	if len(ip1) != len(ip2) {
		return false
	}

	mask := net.CIDRMask(maskBits, len(ip1)*8)
	for i := 0; i < len(ip1); i++ {
		if (ip1[i] & mask[i]) != (ip2[i] & mask[i]) {
			return false
		}
	}

	return true
}

func validateSessionIP(sessionIP, currentIP string) bool {
	return sessionIP == currentIP // Exact match required
}

// GetTokenBlacklistSize returns the number of tokens in the blacklist
func GetTokenBlacklistSize() int {
	tokenBlacklist.mu.RLock()
	defer tokenBlacklist.mu.RUnlock()
	return len(tokenBlacklist.revokedTokens)
}

// IsJWTRevoked checks if a JWT token is revoked by its ID
func IsJWTRevoked(jwtID string) bool {
	return tokenBlacklist.IsTokenRevoked(jwtID)
}
