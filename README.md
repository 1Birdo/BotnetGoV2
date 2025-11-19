# BotnetGoV2

A Command & Control (C&C) system for network testing and resilience evaluation. The system is built for scalability, security, and operational efficiency.

**Disclaimer:** This tool is for educational and authorized security testing only. Unauthorized use is prohibited.

## C2 Screenshots
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

## API Server and Usage

For API documentation, see the bottom of this readme.

## PuTTY Version

An alternative PuTTY-based variant exists in a separate project. The primary differences are in communication protocols and bot management. The PuTTY variant is currently private.

## Key Features

* High-performance implementation built with Go for concurrent operations
* TLS 1.3 enforcement with bcrypt password hashing and JWT session management
* Role-Based Access Control (RBAC) with granular permissions
* Comprehensive Layer 4 and Layer 7 attack methods
* Real-time monitoring and diagnostics for connected bots

## Operator Terminal

Operators interact with the C&C system through a secure terminal interface using the following commands.

## Bot Screenshots
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/643b539a-a641-4aaa-883c-fe5d69f040a3" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/2153b117-06e0-484d-81ca-84ff48f41ccb" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/646c2a92-220f-4003-b981-44d915313e44" width="100%"/></td>
  </tr>
</table>

[Watch Demo Video](https://github.com/user-attachments/assets/7c0a1ad8-73c5-45dc-bcc4-ef36e500a348)

## Core Security & Architecture

The system uses a dual server architecture to segregate bot and operator traffic. When the API server is active, this becomes a triple architecture.

### Architecture Summary

| Component | Purpose | Protocol & Port |
| :--- | :--- | :--- |
| **Bot Listener** | Manages bot connections | Custom Binary/TLS on `7002` |
| **User/Admin Listener** | Handles operator connections | Custom/TLS on `420` |
| **API Server** | Provides programmatic control | HTTPS REST API on `8080` |

### Security Implementation

* **Authentication:** bcrypt password hashing with constant-time comparisons
* **Session Management:** JWT tokens with refresh, revocation, and IP validation
* **TLS:** Enforces TLS 1.3 with modern cipher suites
* **Resource Management:** Bounded data structures prevent memory exhaustion

## Terminal Commands

### Basic Commands

| Command | Description |
|---|---|
| `help` | Lists all available commands |
| `clear` | Clears the terminal screen |
| `bots` | Displays total connected bots |
| `botstatus` | Shows bot telemetry dashboard |
| `methods` | Lists available attack methods based on role |
| `gif` | Plays terminal animation from `.tfx` file |

### Attack & User Management

| Command | Description |
|---|---|
| `ongoing` | Displays currently running attack |
| `allattacks` | Lists all active attacks on the server |
| `attackhistory` | Shows past attack history |
| `stopattack` | Terminates current attack |
| `users` | Lists all user accounts (Admin/Owner) |
| `adduser` | Creates new user account (Admin/Owner) |
| `deluser` | Deletes user account (Admin/Owner) |
| `rbac` | Manages RBAC permissions (Admin/Owner) |
| `!reinstall`| Commands all bots to reinstall (Owner) |

## Attack Commands

Attack commands use the format: `!<method> <target> <duration> [options...]`

**Example:** `!http get https://example.com 60`

### Available Methods

**Layer 4 Floods:**
* `!udp`, `!udpsmart` - UDP packet floods
* `!tcp`, `!syn`, `!ack`, `!rst` - TCP packet floods
* `!gre` - GRE packet floods

**Layer 4+ (Advanced) Floods:**
* `!vse` - Valve Source Engine query flood
* `!xmas` - Christmas Tree packet flood
* `!pps` - Packets-Per-Second bypass flood
* `!stomp` - TCP Stomp flood

**Amplification Attacks:**
* `!amp` - DNS Amplification

**Application Layer (Layer 7) Attacks:**
* `!http` - HTTP request floods

The system blocks attacks against private, local, or reserved IP addresses.

## User Roles & Permissions

| Role | Access Level | Capabilities |
|---|---|---|
| **Owner** | Full System Control | Complete system management and configuration |
| **Admin** | Elevated Administration | User management and method authorization |
| **Pro** | Advanced Operator | High-impact attack methods |
| **Basic** | Standard Operator | Fundamental methods (`!udp`, `!http`) |

## REST API

The REST API provides programmatic control and automation.

**Authentication:** API Token & Secret required

**Key Endpoints:**
* `POST /api/attack` - Launch attacks
* `GET /api/bots` - List connected bots
* `GET /api/stats` - Retrieve server statistics
