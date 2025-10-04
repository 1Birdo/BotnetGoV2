# 🔱 BotnetGoV2

Welcome to BotnetGo! This is a powerful and secure Command & Control (C&C) system designed for network security testing and resilience validation. It's built to be scalable, secure, and easy to use.

**⚠️ Disclaimer:** This tool is intended for educational and authorized security testing purposes only. Unauthorized use is strictly prohibited.

## 🖥️ C2 Closeups
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

## 🚫[  **API server / Usage**  ]   
If you are look for the API section please check the bottom of the 'Readme.md'

## 🖥️ PuTTY
For the PuTTY variant of this project, please refer to my Alternatives Project for the supported version. The only difference lies in how communication is handled and how the bots are managed.  The Current PuTTY varient of BotnetGoV2 is privated due to some abuse.

---

## ✨ Key Features

*   **High-Performance:** Built with Go for speed and concurrency.
*   **Secure by Design:** Enforces TLS 1.3, hashed credentials, and JWT for secure sessions.
*   **Role-Based Access Control (RBAC):** Fine-grained permissions for different user levels.
*   **Powerful Attack Suite:** A comprehensive set of Layer 4 and Layer 7 attack methods.
*   **Real-Time Monitoring:** Live diagnostics and health status of all connected bots.

## 💻 Getting Started: The Operator Terminal

As an operator, you'll interact with the C&C system through a secure terminal interface. Here are the commands you'll use to manage the botnet and send tasks.

## 🖥️ Bot Closeups
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/643b539a-a641-4aaa-883c-fe5d69f040a3" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/2153b117-06e0-484d-81ca-84ff48f41ccb" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/646c2a92-220f-4003-b981-44d915313e44" width="100%"/></td>
  </tr>
</table>

<a href="https://github.com/user-attachments/assets/7c0a1ad8-73c5-45dc-bcc4-ef36e500a348">
  <img src="https://img.shields.io/badge/▶_Watch_Video-blue?style=for-the-badge" />
</a>

> ^ **Please Click** For a actual Demo / Visual Look

---

## 🛡️ Core Security & Architecture

The system uses a **Dual Server Architecture** to segregate bot and operator traffic, maximizing stability and control.

> This is technically A **Triple Architecture** if you use / maintain usage of the API. But i dont really count it.

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

## 💻 Getting Started: The Operator Terminal

As an operator, you'll interact with the C&C system through a secure terminal interface. Here are the commands you'll use to manage the botnet and orchestrate tasks.

### Basic Commands

These commands help you get information and manage the terminal.

| Command | Description |
|---|---|
| `help` | Shows a list of all available commands. Your best friend! |
| `clear` | Clears the terminal screen for a fresh view. |
| `bots` | Displays the total number of currently connected bots. |
| `botstatus` | Shows a detailed dashboard of bot telemetry data. |
| `methods` | Lists all the attack methods *you* are allowed to use based on your role. |
| `gif` | Plays a terminal animation from a `.tfx` file. |

### Attack & User Management

These commands are for monitoring attacks and managing user accounts.

| Command | Description |
|---|---|
| `ongoing` | See the attack *you* are currently running. |
| `allattacks` | View all attacks currently running on the server. |
| `attackhistory` | Review a history of past attacks. |
| `stopattack` | Stops the attack you are currently running. |
| `users` | Lists all user accounts on the system. (Requires Admin/Owner role). |
| `adduser` | Create a new user account. (Requires Admin/Owner role). |
| `deluser` | Deletes a user. (Requires Admin/Owner role). |
| `rbac` | Manage Role-Based Access Control for methods. (Requires Admin/Owner role). |
| `!reinstall`| Sends a command to all bots to reinstall themselves. (Requires Owner role). |

## 💥 Launching an Attack

To launch an attack, you use a command starting with `!`. All attack commands follow a simple structure: `!<method> <target> <duration> [options...]`

**Example:** `!http get https://example.com 60`

This command tells the bots to send HTTP GET requests to `https://example.com` for 60 seconds.

### Available Attack Methods

Here are the types of stress tests you can run:

*   **Layer 4 Floods:**
    *   `!udp`, `!udpsmart`: Flood a target with UDP packets.
    *   `!tcp`, `!syn`, `!ack`, `!rst`: Flood a target with different types of TCP packets.
    *   `!gre`: Flood a target with GRE packets.
*   **Layer 4+ (Advanced) Floods:**
    *   `!vse`: Valve Source Engine query flood.
    *   `!xmas`: Christmas Tree packet flood.
    *   `!pps`: Packets-Per-Second bypass flood.
    *   `!stomp`: TCP Stomp flood.
*   **Amplification Attacks:**
    *   `!amp`: DNS Amplification attack.
*   **Application Layer (Layer 7) Attacks:**
    *   `!http`: Flood a web server with HTTP requests. (Note: This is listed under Layer 4 in the code, but is a Layer 7 attack).

**Important:** The system automatically blocks attacks against private, local, or reserved IP addresses to ensure safety.

## 👑 User Roles & Permissions

The system has a simple role-based system to control who can do what.

| Role | Access Level | What they can do |
|---|---|---|
| **Owner** | Full System Control | The boss. Can manage everything and everyone. |
| **Admin** | Elevated Administration | Manages users and can authorize all attack methods. |
| **Pro** | Advanced Operator | Can use a powerful subset of high-impact attack methods. |
| **Basic** | Standard Operator | Can use fundamental methods like `!udp` and `!http`. |

## 🤖 For Advanced Users: The REST API

A secure REST API is available for automation and integration with other tools.

*   **Authentication:** Requires an API Token & Secret.
*   **Key Endpoints:**
    *   `POST /api/attack`: Programmatically launch an attack.
    *   `GET /api/bots`: Get a list of all connected bots.
    *   `GET /api/stats`: Fetch server performance and botnet statistics.
