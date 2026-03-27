## BotnetGoV2 (Deprecated Project)

A Command & Control (C2) system for network testing and resilience evaluation. Built in Go for performance and cross-platform support.

**Disclaimer:** This tool is for educational and authorized security testing only. Unauthorized use is prohibited.

## Screenshots
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/9108315d-bfde-43be-bdd7-a563299db175" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/1848a6c8-9058-42c1-b8cf-bdb6b1b8f302" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/072342a1-6a15-4b2d-8292-04e26372d738" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/8349fcbb-a2b9-4dee-a7ad-131646209f05" width="100%"/></td>
  </tr>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/a873f3ce-0ade-45a3-9a5b-a45e34426d12" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/df4f3bb9-cb84-4772-b066-64ec02984fd5" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/2153b117-06e0-484d-81ca-84ff48f41ccb" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/c9d9da63-daa6-40d4-9911-fe22cd33e13b" width="100%"/></td>
  </tr>
</table>

[Watch Demo Video](https://github.com/user-attachments/assets/7c0a1ad8-73c5-45dc-bcc4-ef36e500a348)

## Project Layout

```
├── cnc/                 # C2 server
│   ├── cfg.go           # constants / config
│   ├── types.go         # shared type definitions
│   ├── main.go          # entry point, TLS listeners
│   ├── tui.go           # terminal UI, command loop, animations
│   ├── auth.go          # user auth, bcrypt, quotas
│   ├── token.go         # JWT sessions, refresh, revocation
│   ├── acl.go           # RBAC permission system
│   ├── bots.go          # bot registry, heartbeat, diagnostics
│   ├── wire.go          # binary packet protocol
│   ├── api.go           # REST API (HTTPS)
│   ├── pool.go          # TLS connection pooling
│   ├── store.go         # thread-safe bounded collections
│   ├── throttle.go      # rate limiting
│   ├── log.go           # structured logging
│   ├── check.go         # input validation
│   └── data/
│       ├── certs/       # TLS certs (server.crt, server.key)
│       ├── geo/         # MaxMind GeoIP databases
│       ├── gifs/        # terminal animations (.tfx)
│       ├── json/        # rbac.json, users.json
│       └── logs/        # runtime logs
│
├── device/              # bot client
│   ├── bot.go           # bot logic, packet protocol, attack methods
│   └── build.sh         # cross-compile for linux targets
│
├── gifs/                # source .gif files
├── gif.py               # GIF → TFX converter
└── tut.md               # setup & usage guide
```

## Architecture

| Component | Port | Protocol |
|:---|:---|:---|
| Bot listener | `7002` | Custom binary over TLS |
| User terminal | `420` | ANSI TUI over TLS |
| REST API | `8443` | HTTPS |

## Security

- TLS 1.3 enforced on all connections
- bcrypt password hashing with constant-time comparison
- JWT sessions with refresh tokens, revocation, and IP binding
- RBAC with per-method granularity
- Rate limiting on auth, attacks, API, commands, and connections
- Bounded data structures to prevent memory exhaustion
- Input validation on all user-supplied data

## Quick Start

### C2 Server

```bash
cd cnc
# place server.crt + server.key in data/certs/
go build -o c2 .
./c2
```

### Bot Client

Edit the C2 address in `device/bot.go`, then:

```bash
cd device
go build -o bot .
./bot
```

Cross-compile for IoT targets:

```bash
cd device
chmod +x build.sh
./build.sh
# binaries in build/
```

### GIF Converter

```bash
pip install Pillow numpy
python gif.py gifs/crow.gif cnc/data/gifs/crow.tfx
```

## Terminal Commands

| Command | Description |
|:---|:---|
| `help` | Show command list |
| `bots` | Connected bot count |
| `botstatus` | Bot telemetry dashboard |
| `methods` | Available attack methods |
| `ongoing` | Current attack status |
| `allattacks` | All active attacks |
| `stopattack` | Stop running attack |
| `attackhistory` | Past attacks |
| `gif list` | List animations |
| `gif <name>` | Play animation |
| `clear` | Clear screen |
| `logout` | Disconnect |

### Admin / Owner

| Command | Description |
|:---|:---|
| `adduser` | Create user account |
| `deluser` | Delete user account |
| `users` | List all users |
| `rbac` | View/edit permissions |
| `admin` | Admin command panel |
| `owner` | Owner command panel |
| `!reinstall` | Reinstall all bots (owner) |

### Attack Methods

Format: `!method ip port duration`

**Layer 4:** `!udp` `!udpsmart` `!tcp` `!syn` `!ack` `!rst` `!gre`

**Layer 4+:** `!vse` `!xmas` `!pps` `!stomp`

**Amplification:** `!amp`

## REST API

Auth: API token + secret (generated per user via `adduser`)

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/attack` | Launch attack |
| `GET` | `/api/bots` | List bots |
| `GET` | `/api/stats` | Server stats |

## User Roles

| Role | Access |
|:---|:---|
| Owner | Full system control |
| Admin | User management, method auth |
| Pro | All attack methods |
| Basic | `!udp`, `!tcp` only |
