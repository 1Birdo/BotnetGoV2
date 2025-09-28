# Go Botnet Project - Comprehensive Guide

## 1. Project Overview

Welcome to the Go Botnet project. This document provides a comprehensive guide to understanding, setting up, and operating the Command and Control (C2) server and the associated bot clients. The system is designed for remote device management and monitoring, built entirely in Go for performance and cross-platform compatibility.

### Key Features

*   **Command & Control (C2) Server:** A central server with a terminal-based UI for managing connected bots.
*   **Cross-Platform Bot:** The bot client is designed to be compiled for multiple architectures (x86, ARM, MIPS), making it suitable for various IoT devices and servers.
*   **Secure Communication:** All communication between the C2 and bots is encrypted using TLS.
*   **Custom Binary Protocol:** A lightweight and efficient binary protocol for sending commands, heartbeats, and diagnostic data.
*   **Device Diagnostics:** Bots can report system information like OS, architecture, CPU, memory, and uptime.
*   **Extensible Utilities:** Includes Python scripts for converting media into a terminal-friendly format.

### Repository Structure

The project is organized into the following main directories:

```plaintext
/
├── cnc/                # C2 Server Source Code and Data
│   ├── main.go         # C2 server entry point
│   ├── *.go            # Core C2 source files (networking, session management, etc.)
│   └── data/           # C2 data files
│       ├── certs/      # SSL/TLS certificates (server.crt, server.key)
│       ├── geo/        # GeoIP database files for location mapping
│       ├── gifs/       # Terminal-ready .tfx animation files
│       ├── json/       # User and RBAC configuration (users.json, rbac.json)
│       └── logs/       # System and user activity logs
│
├── device/             # Bot/Client Source Code
│   ├── bot.go          # Main bot logic and communication protocol
│   └── build.sh        # Build script for cross-compiling the bot
│
├── gifs/               # Original, source .gif files
│
└── gif.py              # Python utility to convert GIFs to .tfx format
```

---

## 2. The C2 (Command and Control) Server

The C2 server is the brain of the operation, providing the interface to manage and task connected bots.

### Prerequisites

*   **Go:** Version 1.16 or newer installed and configured.

### Configuration

Before running the C2, ensure the following are correctly configured in the `cnc/data/` directory:

*   **Users & Permissions:**
    *   `json/users.json`: Defines user accounts, password hashes, and roles.
    *   `json/rbac.json`: (Role-Based Access Control) Defines permissions for different user roles.
*   **SSL/TLS Certificates:** The server requires `server.crt` and `server.key` in the `certs/` directory for secure TLS communication.
*   **GeoIP Database:** Place MaxMind DB files (`.mmdb`) in the `geo/` directory to enable IP-to-location mapping for connected bots.
*   **GIFs:** The C2 can display animated GIFs in the terminal. These must be converted to the `.tfx` format using the `gif.py` utility and placed in the `gifs/` directory.

### Building the C2

1.  **Navigate to the C2 directory:**
    ```bash
    cd cnc
    ```

2.  **Initialize Go modules and tidy dependencies** (if needed):
    ```bash
    go mod init C2
    go mod tidy
    ```

3.  **Build the executable:**
    This command compiles the source code and creates an executable file (e.g., `c2.exe` on Windows or `c2` on Linux).
    ```bash
    go build .
    ```

### Running the C2

*   **Run the compiled executable:**
    ```bash
    # On Windows
    .\c2.exe

    # On Linux/macOS
    ./c2
    ```

*   **Alternatively, build and run in one step:**
    ```bash
    go run .
    ```

---

## 3. The Bot/Device Client

The bot is a lightweight client that runs on target devices, connects back to the C2, and awaits commands.

### Prerequisites

*   **Go:** Version 1.16 or newer installed for compilation.

### Configuration

> **⚠️ IMPORTANT: Hardcoded Values**
> Before compiling the bot, you **must** edit `device/bot.go` to set the C2 server address and a unique Bot ID. These are currently hardcoded for simplicity.
>
> ```go
> // In device/bot.go, inside the main() function
> func main() {
>     // 1. Change the Bot ID to a unique identifier for the device.
>     // 2. Change the IP address and port to match your C2 server.
> 	bot := NewBot("UNIQUE_BOT_ID_HERE", "YOUR_C2_IP_ADDRESS:7002")
> 	bot.Start()
> }
> ```

### Building the Bot for Multiple Platforms

The `device/build.sh` script is provided to cross-compile the bot for various common Linux architectures.

1.  **Navigate to the device directory:**
    ```bash
    cd device
    ```

2.  **Make the build script executable** (on Linux/macOS):
    ```bash
    chmod +x build.sh
    ```

3.  **Run the build script:**
    ```bash
    ./build.sh
    ```

This will generate multiple binaries in the `device` directory, each named for its target architecture (e.g., `x86`, `armv7l`, `mips`). The script uses Go's cross-compilation features by setting `GOOS` and `GOARCH` environment variables.

---

## 4. Communication Protocol

The project uses a custom binary protocol for efficient and low-overhead communication.

*   **Structure:** Packets consist of a fixed-size header and a variable-length payload.
    *   **Header (19 bytes):** Contains Packet Type, Payload Length, Timestamp, and a Checksum.
    *   **Payload:** Contains the actual data, such as a command or diagnostic info.
*   **Packet Types:**
    *   `Ping/Pong`: Used for checking connectivity.
    *   `Command`: Sent from C2 to bot to execute tasks.
    *   `Heartbeat`: Sent periodically by the bot to show it's online.
    *   `Diagnostic`: Sent by the bot with system information.
    *   `Auth`: The initial packet sent by a bot to authenticate with the C2.

---

## 5. Utilities

### `gif.py` - GIF to TFX Converter

This Python script converts standard `.gif` files into a special `.tfx` format that can be rendered in a terminal, allowing the C2 to display animations.

#### Prerequisites

*   **Python 3**
*   **Pillow Library:** `pip install Pillow`
*   **NumPy Library:** `pip install numpy`

#### Usage

Run the script from the project's root directory.

```bash
python gif.py <input_gif_path> <output_tfx_path>
```

**Example:** To convert `crow.gif` for the C2:
```bash
python gif.py gifs/crow.gif cnc/data/gifs/crow.tfx
```

You can also specify the terminal dimensions for the output:
```bash
python gif.py gifs/Love.gif cnc/data/gifs/love.tfx --width 80 --height 24
```
