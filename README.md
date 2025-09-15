# BotnetGoV2
The Better Version of the BotnetGO, Eg. Gifs, Secure Login and more++

#Sneek Peek:
# This is a really old sneak peak 

![Gif feature](https://github.com/user-attachments/assets/2116bf5c-b4ff-4eac-80d3-7a02ebf34243)


<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-lightblack" />
</p>


A robust, animated Terminal User Interface (TUI), a central botnet server, and a set of DDoS attack vectors.

Disclaimer: This software is provided for educational and research purposes only. 
Unauthorized use against networks or systems you do not own is illegal and unethical. 
The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## ✨ Features
 
TLS Implementation: Proper use of TLS 1.3 with strong cipher suites
Authentication: Secure password hashing (bcrypt + SHA256 with salt)
Rate Limiting: Comprehensive rate limiting system for various operations
Input Validation: Good validation for IP addresses, ports, and user input
Session Management: Secure session tokens with IP validation
RBAC System: Role-based access control implementation
Logging: Extensive logging system for security events
Connection Limits: IP-based connection limiting

<pre>

   ┌──────────────────────────────────────────────────────────────────────────────┐
   │  🖥️  Advanced Terminal User Interface (TUI)                                  │
   ├──────────────────────────────────────────────────────────────────────────────┤
   │ 1. Rich ANSI Art & Animations                                                │
   │    Includes loading spinners, success indicators, attack animations,         │
   │    and progress bars.                                                        │
   │                                                                              │
   │ 2. Real-time Title Updates                                                   │
   │    Dynamic title bar showing bot count, active attacks, and username.        │
   │                                                                              │
   │ 3. Text Fading & Centered Animations                                         │
   │    For a polished and professional user experience.                          │
   │                                                                              │
   │ 4. Box-drawn Menus                                                           │
   │    Clean, formatted boxes for displaying information like user lists,        │
   │    attack history, and help menus.                                           │
   │                                                                              │
   │ 5. Session Clearing                                                          │
   │    cls command to refresh the terminal view.                                 │
   └──────────────────────────────────────────────────────────────────────────────┘
   
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │ 👤  User Management & Authentication                                         │
   ├──────────────────────────────────────────────────────────────────────────────┤
   │ 1. Multi-user System                                                         │
   │    Supports multiple users with different permission levels                  │
   │    (Owner, Admin, Pro, Basic).                                               │
   │                                                                              │
   │ 2. Secure Login                                                              │
   │    Users authenticate via TLS-encrypted connections.                         │
   │                                                                              │
   │ 3. JSON-based Storage                                                        │
   │    User credentials and expiration dates are stored in a users.json file.    │
   │                                                                              │
   │ 4. Admin User Management                                                     │
   │    Commands to adduser, deluser, and list all existing users.                │
   └──────────────────────────────────────────────────────────────────────────────┘
               
</pre>

## 🤖 Botnet Architecture
## Dual Server Design:
```bash
User Server: Handles administrator logins and command input on port 420.
Bot Server: Accepts connections from compromised bots/clients on port 7002.

TLS Encryption: All communication between the C2 and bots/users is encrypted using TLS 1.3.

Ping Keep-alive: Regular ping packets are sent to bots to ensure they are alive and connected.
Real-time Bot Count: The interface continuously displays the number of connected bots.
```
## ⚔️ Attack Methods & Features
## Multiple DDoS Vectors: Supports a variety of flooding techniques:
```bash
!udpflood, !udpsmart
!tcpflood
!synflood
!ackflood
!greflood

!dns (DNS Amplification)
!http (HTTP Flood)
```
## 🏢 Attack Management:
## Launch Attacks: Simple command structure: [method] [ip] [port] [duration(s)].
```bash
Visual Feedback: Animated progress bars show the status of ongoing attacks.
Stop Attacks: Ability to halt a running attack with the stopattack command.

Attack History: View a log of all past attacks launched from the panel.
Global View: The allattacks command shows every ongoing attack from all users.
```

## 🎭 Entertainment & Extras
```bash
 Integrated GIF Player: Play ASCII art animations (.tfx files) stored in the TermFX/Gifs/ directory using the gif command.

  gif list - Lists all available animations.

  gif [filename] - Plays the specified animation.
       ├── Eg: nuke.tfx
       ├── Eg: nuke
       ├── Eg: example.tfx
       └── Eg: example
```

## 🗂️ Project Structure
```bash
BotnetGoV2/
├── main.go                # Primary application entry point, server initialization, connection handlers.
├── tui.go                 # Terminal User Interface logic: animations, boxes, progress bars.
├── gifs.go                # Functionality for loading and displaying ASCII GIFs.
├── miscellaneous.go       # Helper functions: authentication, user struct, random string gen.
├── users.json             # User database (generated on first run with a random 'root' password).
├── server.crt             # TLS Certificate (You must generate this).
├── server.key             # TLS Private Key (You must generate this).
├── go.mod
└── TermFX/
    └── Gifs/              # Directory for storing ASCII art animation files.
        ├── example.tfx    # The Gif.py is used to make the .tfx files from your chosen gif
        └── Gif.py          
```
        
## 🚀 Getting Started
## Prerequisites
```
Go (Golang) installed on your system (version 1.18+ recommended).
Basic knowledge of the command line and building Go applications.
```
## Installation & Setup
## Clone the Repository

```bash
git clone https://github.com/1Birdo/BotnetGoV2.git
cd BotnetGoV2

go build main.go tui.go gifs.go miscellaneous.go

    [Try both if needed]

go build *.go 
```
## Generate TLS Certificates
## The server requires TLS certificates to run. You can generate self-signed certificates for testing using OpenSSL.

```bash
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out server.crt -keyout server.key
```

4. First Run & Default User
```bash
On the first run, the server will generate a users.json file with a default 
   root user and a random 12-character password. This will be displayed in the console.
```
```text
[☾☼☽] Login with username root and password AbCdEfGhIjKlM
```
Usage
1. Starting the Server
```bash
Run the compiled binary. It will start listening on the configured IPs and ports.
```
```bash
./botnetgov2

[☾☼☽] User server started on 192.168.0.11:420
[☾☼☽] Bot server started on 192.168.0.11:7002
```
2. Connecting as a User
```text
Use a TLS-enabled client to connect. You can use openssl s_client or a custom bot client designed for users.
You will be prompted to enter the username and password generated on the first run, 
You can also add or delete users manually if needed, but remember to keep to the same structure 
```
```text
openssl s_client -connect 192.168.0.11:420 -quiet
```
3. Available Commands
```text
Once authenticated, you will see a prompt [Prompt]►. Type help to see all available commands.
```

   Command | Description | User Level
   --- | --- | ---
   !METHOD IP PORT DURATION | Launch an attack (e.g., !udpflood 1.1.1.1 80 60) | Basic+
   bots | Show the current count of connected bots | All
   ongoing | Show your currently running attack | All
   allattacks | Show all attacks currently running by all users | All
   attackhistory | Show the history of your past attacks | All
   stopattack | Stop your currently running attack | All
   methods or ? | List all available attack methods | All
   gif list | List all available terminal GIFs | All
   gif <filename> | Play a specific terminal GIF | All
   users | List all users on the system | Admin+
   adduser | Add a new user | Admin+
   deluser | Delete a user | Admin+
   clear / cls | Clear the terminal screen | All
   logout / exit | Log out of the session | All


## Bot Client
```text
You can use a separate bot / client if required to connect to the Bot Server port (7002). A client is 
included in this repository as a working example. Its general responsibilities are:
Connect to the C&C server using TLS.

Authenticate if required (optional, not implemented yet).
Listen for the PING packet and respond with PONG to stay connected.

Listen for CommandPacket structures and execute the corresponding
 attack against the specified target for the given duration and input.
```

The development of the bot client is a separate project 
but will be improved now and again and SHOULD work for each project, 
as they are their own.

## FAQ
```text
Q: I get "Error loading TLS certificates" when starting.

A: You must generate the server.crt and server.key files before running the server.
   See the "Installation & Setup" section.

Q: How do I change the server IP?

A: Modify the USER_SERVER_IP and BOT_SERVER_IP constants at the top of main.go
   to 0.0.0.0 to listen on all interfaces or to your specific IP.

Q: A user's attack finished but it's still in allattacks?

A: The allattacks command filters out finished attacks. 
   The list updates in real-time based on the calculated remaining duration.

Q: Can I add my own attack methods?

A: Yes, but it requires modifying both the C&C server (to accept the new command) 
   and the bot client (to understand and execute the new method).
```

## License
## This project is provided for educational purposes only. There is no license granted for public use, redistribution, or modification.
