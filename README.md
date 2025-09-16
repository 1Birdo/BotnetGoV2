# Botnet Control & Management System

## Overview & Architecture

**Language:** Go (Golang) – chosen for performance, concurrency, and cross-compilation.  

**Protocol:** Custom binary protocol over TLS 1.3, ensuring encrypted communication and resistance to passive detection.  

### Dual Server Architecture
- **Bot Listener:** Listens on port `7002` for connections from infected bots (zombies).  
- **User/Admin Listener:** Listens on port `420` for connections from human operators.  
- **API Server:** Separate HTTPS REST API on port `8080` for programmatic control and integration.  

**Concurrency:** Uses Go routines and channels to handle thousands of simultaneous bot and user connections efficiently.  

---

## Core Features & Capabilities

### 1. Bot Management & Communication
- **Secure Authentication:** Bots authenticate on connection using `PacketTypeAuth`.  
- **Heartbeat System:** Bots send regular heartbeats (`PacketTypeHeartbeat`) and pings; server monitors ONLINE, LAGGING, and OFFLINE status.  
- **Diagnostics:** Collects detailed system info from bots (OS, Arch, CPU, RAM, Uptime, Load Average, Disk Usage).  
- **Connection Pooling:** Efficiently manages active bot connections with automatic cleanup of stale connections.  
- **Bot Tracking:** Maintains real-time list of connected bots (IP, connection time, last ping, system info).  

### 2. Attack Orchestration
- **Supported Methods:**  
  `!udpsmart`, `!udpflood`, `!tcpflood`, `!synflood`, `!ackflood`, `!greflood`, `!dns`, `!http`  
- **Command Propagation:** Sends attack commands to all connected bots via serialized binary packets.  
- **Attack Management:**  
  - Tracks ongoing attacks and remaining duration.  
  - Maintains history of past attacks.  
  - Allows users to stop their own attacks (`stopattack`).  
- **Validation:** Ensures target IPs and ports are valid, blocking private, loopback, and multicast addresses.  

### 3. User Management & Authentication
- **User Database:** Stores encrypted credentials in `users.json`.  
- **Secure Authentication:** Uses bcrypt for password hashing.  
- **Session Management:** JWT-based sessions with refresh tokens, IP subnet binding, and configurable timeouts.  
- **Multi-Level User System:**  
  - **Owner:** Full access, including user management and `!reinstall`.  
  - **Admin:** Can manage users and all attack methods.  
  - **Pro:** Access to powerful methods subset.  
  - **Basic:** Access to basic methods like `!udpflood` and `!http`.  
- **API Access:** Each user has unique API Token & Secret for REST API.  

### 4. Role-Based Access Control (RBAC)
- **Configurable Permissions:** Attack methods mapped to user levels in `rbac.json`.  
- **Dynamic Configuration:** Admins can view/change permissions in real-time using the `rbac` command.  

### 5. REST API Server
- **Secure HTTPS API:**  
  - `POST /api/attack` – Launch an attack.  
  - `GET /api/bots` – List all bots.  
  - `GET /api/stats` – Server statistics.  
- **Authentication:** API Token & Secret in headers or query parameters.  
- **Rate Limiting:** Endpoints protected by rate limiting system.  

### 6. Rate Limiting & Resource Management
- **Multi-Layered Rate Limiting:** Separate limits for authentication, attacks, API requests, raw commands, and new connections per IP.  
- **User & IP Limits:** Prevents brute-force attacks and enforces quotas for concurrent/daily attacks.  

### 7. Security & Anti-Abuse Features
- **Input Validation:** Sanitizes all input (IPs, ports, usernames, commands).  
- **Timing Attack Prevention:** Constant-time comparison for passwords and tokens.  
- **Token Blacklisting:** JWT tokens can be revoked early.  
- **Connection Limits:** Limits excessive connections to admin panel.  
- **Secure TLS Config:** Enforces TLS 1.3 with modern ciphers and perfect forward secrecy.  

### 8. Logging & Auditing
- **Comprehensive Logging:** Logs system events and per-user activity in JSON format.  
- **Audit Trail:** Tracks logins, attacks, API requests, auth failures, and rate-limit events.  

### 9. Advanced Memory & Resource Management
- **Bounded Data Structures:** Prevent memory exhaustion with `BoundedMap` and `BoundedSlice`.  
- **Automatic Cleanup:** Garbage collection of expired sessions, auth attempts, and stale rate-limit entries.  

### 10. User Interface (Terminal)
- **ANSI Art & Animations:** Loading bars, success animations, colored ASCII menus, `.tfx` GIF-like sequences.  
- **Interactive Commands:**
```text
bots - Show bot count
methods - List available attack methods
attackhistory - Show history of attacks
ongoing - Show current attack
allattacks - Show all ongoing attacks
botstatus - Show detailed bot statuses
users/adduser/deluser - User management (Admin+)
clear - Clear terminal
help - Show help menu
```


```yaml

## Technical Specifications
- **Max Bot Connections:** 50,000  
- **Max Sessions:** 10,000  
- **Max Attack History Entries:** 10,000  
- **Max Ongoing Attacks:** 1,000  
- **Session Timeout:** 30 minutes  
- **Auth Lockout:** 5 minutes after 3 failed attempts  
```

> ⚠ **Disclaimer:** This repository contains sensitive software for educational purposes only. Unauthorized deployment or use for attacking systems without consent is illegal and strictly prohibited. Only use in controlled lab environments.

