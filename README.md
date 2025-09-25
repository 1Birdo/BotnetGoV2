# 🔱 BotnetGoV2

An enhanced, high-performance C2 (Command and Control) system built in Go (Golang), focusing on security, concurrency, and robust resource management.

[![Demo Preview]](https://github.com/user-attachments/assets/cf1d4a33-b106-4858-ae98-15c67a6d3a43)
    

^ **Please Click** For a actual Demo / Visual Look

> ⚠️ **Disclaimer:** This software is for **educational and authorized security research purposes only**. Use in unauthorized or illegal activities is strictly forbidden. Deploy only in controlled laboratory or sanctioned environments.

---

## ✨ Key Capabilities

| Feature | Description |
| :--- | :--- |
| **High Performance** | Built with **Go** for exceptional concurrency and performance, efficiently managing **thousands of bots** using Go routines. |
| **Secure Comms** | Custom **binary protocol over TLS 1.3** ensuring encrypted, secure communication resistant to passive detection. |
| **Robust Security** | Multi-layered **Rate Limiting**, secure **JWT Session Management** with revocation, and extensive **Input Validation**. |
| **RBAC** | **Role-Based Access Control** system (`rbac.json`) for fine-grained user permissions over attack methods. |
| **Flexible Control** | Dual control interfaces: **Terminal UI** for operators and a dedicated **REST API** for programmatic integration. |

---

## 🛡️ Core Security & Architecture

The system uses a **Dual Server Architecture** to segregate bot and operator traffic, maximizing stability and control.

### Architecture Summary

| Component | Purpose | Protocol & Port |
| :--- | :--- | :--- |
| **Bot Listener** | Receives and manages connections from infected bots (zombies). | Custom Binary/TLS on `7002` |
| **User/Admin Listener** | Receives connections from human operators for C&C access. | Custom/TLS on `420` |
| **API Server** | Provides programmatic control and statistics. | **HTTPS REST API** on `8080` |

### Security Highlights
* **Authentication:** `bcrypt` password hashing and secure, constant-time comparisons.
* **Session Management:** JWT tokens with refresh, revocation, and IP validation.
* **TLS:** Enforces **TLS 1.3** with modern cipher suites.
* **Resource Management:** **Bounded Data Structures** (`BoundedMap`, `BoundedSlice`) prevent memory exhaustion from excessive data or logging.

---

## 🛠️ Bot & Attack Management

The system is engineered for reliable diagnostics and powerful attack orchestration.

### Bot Diagnostics
* **Real-time Status:** Tracks bots as **ONLINE**, **LAGGING**, or **OFFLINE** using a heartbeat system.
* **System Info:** Collects detailed diagnostics (OS, Arch, CPU, RAM, Uptime, Load Average, Disk Usage).
* **Connection Pooling:** Efficiently manages active connections, automatically cleaning up stale ones.

### Supported Attack Methods
A comprehensive suite of methods for stress testing and authorized vulnerability research:
* `!udpsmart`, `!udpflood`, `!tcpflood`, `!synflood`, `!ackflood`, `!greflood`, `!dns`, `!http`

### Command Validation
All attack commands are rigorously validated to block private, loopback, and multicast addresses, enforcing a safe operational boundary.

---

## 👤 Operator & Access Control

A multi-level user system ensures separation of duties and granular control.

### User Roles
| Role | Access Level | Key Privilege |
| :--- | :--- | :--- |
| **Owner** | Full | User management + `!reinstall` command |
| **Admin** | High | Manage all users and all attack methods |
| **Pro** | Medium | Access to a powerful subset of attack methods |
| **Basic** | Low | Access to fundamental methods (`!udpflood`, `!http`) |

### Terminal Commands
The interactive **Terminal UI** provides direct control:

| Command | Purpose |
| :--- | :--- |
| `bots` | Show total connected bot count. |
| `ongoing` / `allattacks` | View active attack status and history. |
| `methods` | List available attack methods based on user role. |
| `users` / `adduser` | User management functions (Admin+ required). |
| `help` / `clear` | General terminal utility commands. |

---

## 📊 Technical Specifications

| Parameter | Limit |
| :--- | :--- |
| Max Bot Connections | **50,000** |
| Max Operator Sessions | **10,000** |
| Max Ongoing Attacks | **1,000** |
| Session Timeout | **30 minutes** |
| Auth Lockout | 5 minutes after 3 failed attempts |

---

## 💻 REST API Integration

A dedicated API server allows for easy integration into custom scripts and external tools.

* **Endpoint Examples:**
    * `POST /api/attack` – Launch a new attack.
    * `GET /api/bots` – Retrieve a list of connected bots.
    * `GET /api/stats` – Get server performance and bot statistics.
* **Authentication:** Requires unique **API Token & Secret** passed via headers or query parameters.
