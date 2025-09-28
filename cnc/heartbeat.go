package main

import (
	"sync"
	"time"
)

type HeartbeatManager struct {
	bots map[string]*BotHeartbeat
	mu   sync.RWMutex
}

type BotHeartbeat struct {
	LastHeartbeat time.Time
	Ping          time.Duration
	Status        string // retained for legacy callers but derived dynamically
}

const (
	laggingThreshold = 1 * time.Minute
	offlineThreshold = 2 * time.Minute
)

type BotStatusDetail struct {
	Status        string
	LastHeartbeat time.Time
	PingMS        int64
	Live          bool
}

var heartbeatManager = NewHeartbeatManager()

func NewHeartbeatManager() *HeartbeatManager {
	return &HeartbeatManager{
		bots: make(map[string]*BotHeartbeat),
	}
}

func (hm *HeartbeatManager) UpdateBot(botID string, t time.Time, ping time.Duration) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if bot, exists := hm.bots[botID]; exists {
		bot.LastHeartbeat = t
		if ping > 0 {
			bot.Ping = ping
		}
	} else {
		hm.bots[botID] = &BotHeartbeat{
			LastHeartbeat: t,
			Ping:          ping,
			Status:        "ONLINE",
		}
	}
}

func (hm *HeartbeatManager) RemoveBot(botID string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	delete(hm.bots, botID)
}

func (hm *HeartbeatManager) GetBotCount() int {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	// Legacy: previously returned all tracked bots (including stale/offline)
	// For compatibility keep function but now return only currently "live" bots
	// (those that have sent a heartbeat within the offline threshold window).
	now := time.Now()
	count := 0
	for _, bot := range hm.bots {
		if _, live := classifyHeartbeat(now.Sub(bot.LastHeartbeat)); live {
			count++
		}
	}
	return count
}

func (hm *HeartbeatManager) CheckHeartbeats() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	now := time.Now()
	for _, bot := range hm.bots {
		status, _ := classifyHeartbeat(now.Sub(bot.LastHeartbeat))
		bot.Status = status
	}
}

func (hm *HeartbeatManager) GetBotStatusSummary() map[string]int {
	// Calculate status in real-time based solely on last heartbeat timestamps.
	// This removes dependency on periodic CheckHeartbeats updates so the
	// dashboard always reflects what we are currently "getting from bots".
	summary := map[string]int{
		"ONLINE":  0,
		"LAGGING": 0,
		"OFFLINE": 0,
		"TOTAL":   0, // will represent only live (ONLINE+LAGGING) bots
	}

	hm.mu.RLock()
	now := time.Now()
	for _, bot := range hm.bots {
		status, live := classifyHeartbeat(now.Sub(bot.LastHeartbeat))
		summary[status]++
		if live {
			summary["TOTAL"]++
		}
	}
	hm.mu.RUnlock()

	if summary["TOTAL"] == 0 {
		botInfoLock.RLock()
		fallbackNow := time.Now()
		fallback := 0
		for _, info := range botInfoMap {
			if fallbackNow.Sub(info.LastPing) <= offlineThreshold {
				fallback++
			}
		}
		botInfoLock.RUnlock()

		if fallback > 0 {
			summary["ONLINE"] = fallback
			summary["TOTAL"] = fallback
		}
	}

	return summary
}

func (hm *HeartbeatManager) GetDetailedBotStatus() map[string]BotStatusDetail {
	// Build a snapshot on demand; derive status dynamically from LastHeartbeat.
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	detailedStatus := make(map[string]BotStatusDetail)
	now := time.Now()
	for botID, bot := range hm.bots {
		status, live := classifyHeartbeat(now.Sub(bot.LastHeartbeat))
		detailedStatus[botID] = BotStatusDetail{
			Status:        status,
			LastHeartbeat: bot.LastHeartbeat,
			PingMS:        bot.Ping.Milliseconds(),
			Live:          live,
		}
	}
	return detailedStatus
}

func classifyHeartbeat(delta time.Duration) (status string, live bool) {
	switch {
	case delta > offlineThreshold:
		return "OFFLINE", false
	case delta > laggingThreshold:
		return "LAGGING", true
	default:
		return "ONLINE", true
	}
}

func StartHeartbeatMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			heartbeatManager.CheckHeartbeats()
		}
	}()
}
