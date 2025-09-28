package main

import (
	"crypto/subtle"
	"crypto/tls"
	"net"
	"runtime"
	"sync"
	"time"
)

const (
	MaxBotConnections     = 50000
	MaxSessions           = 10000
	MaxAuthAttempts       = 10000
	MaxUserQuotas         = 1000
	MaxAttackHistory      = 10000
	MaxRateLimitEntries   = 50000
	MaxConnectionPoolSize = 1000
	MaxAPIRequests        = 1000
	MaxOngoingAttacks     = 1000
	MaxOngoingAPIAttacks  = 1000
	MaxMutexes            = 10000
)

type BoundedMap struct {
	data    map[string]interface{}
	maxSize int
	mutex   sync.RWMutex
}

func NewBoundedMap(maxSize int) *BoundedMap {
	return &BoundedMap{
		data:    make(map[string]interface{}),
		maxSize: maxSize,
	}
}

type ResourceManager struct {
	metrics map[string]int64
	mutex   sync.RWMutex
}

func NewResourceManager() *ResourceManager {
	return &ResourceManager{
		metrics: make(map[string]int64),
	}
}

func (rm *ResourceManager) TrackAllocation(resourceType string, size int64) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.metrics[resourceType] += size
}

func (rm *ResourceManager) GetUsage(resourceType string) int64 {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	return rm.metrics[resourceType]
}

var resourceManager = NewResourceManager()

func (bm *BoundedMap) Set(key string, value interface{}) bool {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if len(bm.data) >= bm.maxSize && bm.data[key] == nil {
		return false
	}

	bm.data[key] = value
	return true
}

func (bm *BoundedMap) Get(key string) (interface{}, bool) {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	value, exists := bm.data[key]
	return value, exists
}

func (bm *BoundedMap) Delete(key string) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	delete(bm.data, key)
}

func (bm *BoundedMap) Size() int {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	return len(bm.data)
}

func (bm *BoundedMap) Cleanup(predicate func(key string, value interface{}) bool) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	for key, value := range bm.data {
		if predicate(key, value) {
			delete(bm.data, key)
		}
	}
}

func (bm *BoundedMap) Store(key string, value interface{}) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if len(bm.data) >= bm.maxSize && bm.data[key] == nil {
		return
	}

	bm.data[key] = value
}

func (bm *BoundedMap) Range(f func(key string, value interface{}) bool) {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	for key, value := range bm.data {
		if !f(key, value) {
			break
		}
	}
}

type BoundedSlice struct {
	data    []interface{}
	mutex   sync.RWMutex
	maxSize int
}

func NewBoundedSlice(maxSize int) *BoundedSlice {
	return &BoundedSlice{
		data:    make([]interface{}, 0, maxSize),
		maxSize: maxSize,
	}
}

func (bs *BoundedSlice) Append(value interface{}) bool {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	if len(bs.data) >= bs.maxSize {
		return false
	}

	bs.data = append(bs.data, value)
	return true
}

func (bs *BoundedSlice) Get(index int) (interface{}, bool) {
	bs.mutex.RLock()
	defer bs.mutex.RUnlock()

	if index < 0 || index >= len(bs.data) {
		return nil, false
	}

	return bs.data[index], true
}

func (bs *BoundedSlice) Remove(index int) bool {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	if index < 0 || index >= len(bs.data) {
		return false
	}

	bs.data = append(bs.data[:index], bs.data[index+1:]...)
	return true
}

func (bs *BoundedSlice) Size() int {
	bs.mutex.RLock()
	defer bs.mutex.RUnlock()

	return len(bs.data)
}

func (bs *BoundedSlice) Cleanup(predicate func(value interface{}) bool) {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	newData := make([]interface{}, 0, bs.maxSize)
	for _, value := range bs.data {
		if !predicate(value) {
			newData = append(newData, value)
		}
	}
	bs.data = newData
}

func SecureCompare(a, b string) bool {
	aBytes := []byte(a)
	bBytes := []byte(b)

	if len(aBytes) != len(bBytes) {
		dummy := make([]byte, max(len(aBytes), len(bBytes)))
		subtle.ConstantTimeCompare(aBytes, dummy)
		subtle.ConstantTimeCompare(bBytes, dummy)
		return false
	}

	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

func SecureCompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

type MemoryManager struct {
	allocated     int64
	maxMemory     int64
	allocations   map[uintptr]int64
	allocationMu  sync.RWMutex
	cleanupTicker *time.Ticker
}

func NewMemoryManager(maxMemory int64) *MemoryManager {
	mm := &MemoryManager{
		maxMemory:   maxMemory,
		allocations: make(map[uintptr]int64),
	}

	// Start cleanup routine
	mm.cleanupTicker = time.NewTicker(1 * time.Minute)
	go mm.cleanupRoutine()

	return mm
}

func (mm *MemoryManager) Allocate(size int64) (uintptr, bool) {
	mm.allocationMu.Lock()
	defer mm.allocationMu.Unlock()

	if mm.allocated+size < mm.allocated {
		return 0, false // Overflow
	}

	if mm.allocated+size > mm.maxMemory {
		return 0, false // Exceeds max memory
	}

	ptr := uintptr(mm.allocated) // Simplified pointer simulation
	mm.allocations[ptr] = size
	mm.allocated += size

	return ptr, true
}

func (mm *MemoryManager) Release(ptr uintptr) {
	mm.allocationMu.Lock()
	defer mm.allocationMu.Unlock()

	if size, exists := mm.allocations[ptr]; exists {
		mm.allocated -= size
		if mm.allocated < 0 {
			mm.allocated = 0
		}
		delete(mm.allocations, ptr)
	}
}

func (mm *MemoryManager) GetUsage() int64 {
	mm.allocationMu.RLock()
	defer mm.allocationMu.RUnlock()
	return mm.allocated
}

func (mm *MemoryManager) GetUsagePercentage() float64 {
	mm.allocationMu.RLock()
	defer mm.allocationMu.RUnlock()
	if mm.maxMemory == 0 {
		return 0
	}
	return float64(mm.allocated) / float64(mm.maxMemory) * 100
}

func (mm *MemoryManager) cleanupRoutine() {
	for range mm.cleanupTicker.C {
		mm.allocationMu.Lock()
		// Check for memory leaks or orphaned allocations
		if len(mm.allocations) > 1000 && float64(mm.allocated)/float64(mm.maxMemory) > 0.8 {
			// Force garbage collection if memory usage is high
			runtime.GC()
		}
		mm.allocationMu.Unlock()
	}
}

func (mm *MemoryManager) Close() {
	if mm.cleanupTicker != nil {
		mm.cleanupTicker.Stop()
	}
}

type MutexManager struct {
	mutexes       map[string]*sync.RWMutex
	mutexUsage    map[string]time.Time
	mutexStats    map[string]int64
	mutexMu       sync.RWMutex
	maxMutexes    int
	cleanupTicker *time.Ticker
}

func NewMutexManager(maxMutexes int) *MutexManager {
	mm := &MutexManager{
		mutexes:       make(map[string]*sync.RWMutex),
		mutexUsage:    make(map[string]time.Time),
		mutexStats:    make(map[string]int64),
		maxMutexes:    maxMutexes,
		cleanupTicker: time.NewTicker(5 * time.Minute),
	}

	go mm.cleanupRoutine()
	return mm
}

func (mm *MutexManager) GetMutex(key string) *sync.RWMutex {
	mm.mutexMu.Lock()
	defer mm.mutexMu.Unlock()

	if mutex, exists := mm.mutexes[key]; exists {
		mm.mutexUsage[key] = time.Now()
		mm.mutexStats[key]++
		return mutex
	}

	if len(mm.mutexes) >= mm.maxMutexes {
		mm.cleanupLRU()
	}

	mutex := &sync.RWMutex{}
	mm.mutexes[key] = mutex
	mm.mutexUsage[key] = time.Now()
	mm.mutexStats[key] = 1

	return mutex
}

func (mm *MutexManager) cleanupLRU() {
	var oldestKey string
	var oldestTime time.Time

	for key, lastUsed := range mm.mutexUsage {
		if oldestTime.IsZero() || lastUsed.Before(oldestTime) {
			oldestTime = lastUsed
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(mm.mutexes, oldestKey)
		delete(mm.mutexUsage, oldestKey)
		delete(mm.mutexStats, oldestKey)
	}
}

func (mm *MutexManager) cleanupRoutine() {
	for range mm.cleanupTicker.C {
		mm.mutexMu.Lock()
		now := time.Now()
		for key, lastUsed := range mm.mutexUsage {
			if now.Sub(lastUsed) > 30*time.Minute {
				delete(mm.mutexes, key)
				delete(mm.mutexUsage, key)
				delete(mm.mutexStats, key)
			}
		}
		mm.mutexMu.Unlock()
	}
}

func (mm *MutexManager) GetStats() map[string]interface{} {
	mm.mutexMu.RLock()
	defer mm.mutexMu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_mutexes"] = len(mm.mutexes)
	stats["mutex_usage"] = mm.mutexStats
	return stats
}

func (mm *MutexManager) Close() {
	if mm.cleanupTicker != nil {
		mm.cleanupTicker.Stop()
	}
}

var (
	globalMemoryManager = NewMemoryManager(1024 * 1024 * 1024) // 1GB max
	globalMutexManager  = NewMutexManager(MaxMutexes)

	boundedBotConns          = NewBoundedMap(MaxBotConnections)
	boundedSessions          = NewBoundedMap(MaxSessions)
	boundedAuthAttempts      = NewBoundedMap(MaxAuthAttempts)
	boundedUserQuotas        = NewBoundedMap(MaxUserQuotas)
	boundedAttackHistory     = NewBoundedSlice(MaxAttackHistory)
	boundedRateLimitEntries  = make(map[RateLimitType]*BoundedMap)
	boundedOngoingAttacks    = NewBoundedMap(MaxOngoingAttacks)
	boundedOngoingAPIAttacks = NewBoundedMap(MaxOngoingAPIAttacks)
)

func init() {
	for i := 0; i < int(RateLimitConnection)+1; i++ {
		boundedRateLimitEntries[RateLimitType(i)] = NewBoundedMap(MaxRateLimitEntries)
	}
	go cleanupBoundedCollections()
}

type ThreadSafeBotManager struct {
	bots map[string]*tls.Conn
	// map from connection remote address string to botID to avoid re-authing and duplicate adds
	connToBot map[string]string
	mutex     *sync.RWMutex
}

func NewThreadSafeBotManager() *ThreadSafeBotManager {
	return &ThreadSafeBotManager{
		bots:      make(map[string]*tls.Conn),
		connToBot: make(map[string]string),
		mutex:     &sync.RWMutex{},
	}
}

func (m *ThreadSafeBotManager) AddBot(botID string, conn *tls.Conn) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// If a previous connection exists for this botID, close it and replace
	if oldConn, ok := m.bots[botID]; ok {
		if oldConn != nil {
			oldConn.Close()
		}
		// remove any reverse mapping to the old connection
		for k, v := range m.connToBot {
			if v == botID {
				delete(m.connToBot, k)
			}
		}
	}

	m.bots[botID] = conn
	m.connToBot[conn.RemoteAddr().String()] = botID
	heartbeatManager.UpdateBot(botID, time.Now(), 0)
}

func (m *ThreadSafeBotManager) RemoveBot(botID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if conn, ok := m.bots[botID]; ok {
		delete(m.bots, botID)
		// remove any reverse mapping entries
		for k, v := range m.connToBot {
			if v == botID {
				delete(m.connToBot, k)
				break
			}
		}
		if conn != nil {
			conn.Close()
		}
		heartbeatManager.RemoveBot(botID)
	}
}

// GetBotIDByConn returns the botID associated with a connection (by remote addr), or empty if none
func (m *ThreadSafeBotManager) GetBotIDByConn(conn net.Conn) string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.connToBot[conn.RemoteAddr().String()]
}

func (m *ThreadSafeBotManager) GetBot(botID string) (*tls.Conn, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	conn, ok := m.bots[botID]
	return conn, ok
}

func (m *ThreadSafeBotManager) GetAllBots() map[string]*tls.Conn {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	// Return a copy to avoid race conditions with the caller
	botCopy := make(map[string]*tls.Conn)
	for id, conn := range m.bots {
		botCopy[id] = conn
	}
	return botCopy
}

func (m *ThreadSafeBotManager) Count() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.bots)
}

// Cleanup removes disconnected bots
func (m *ThreadSafeBotManager) Cleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for botID, conn := range m.bots {
		if conn == nil {
			delete(m.bots, botID)
			heartbeatManager.RemoveBot(botID)
			for k, v := range m.connToBot {
				if v == botID {
					delete(m.connToBot, k)
					break
				}
			}
			continue
		}
		// Check if connection is still alive by sending a byte
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if _, err := conn.Write([]byte{}); err != nil {
			delete(m.bots, botID)
			heartbeatManager.RemoveBot(botID)
			for k, v := range m.connToBot {
				if v == botID {
					delete(m.connToBot, k)
					break
				}
			}
			conn.Close()
		}
		conn.SetWriteDeadline(time.Time{})
	}
}

var botManager = NewThreadSafeBotManager()

func cleanupBoundedCollections() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Cleanup BoundedMaps
		boundedBotConns.Cleanup(func(key string, value interface{}) bool {
			// Example: remove if older than 24 hours
			if entry, ok := value.(time.Time); ok {
				return time.Since(entry) > 24*time.Hour
			}
			return false
		})
		boundedSessions.Cleanup(func(key string, value interface{}) bool {
			if s, ok := value.(*Session); ok {
				return time.Now().After(s.ExpiresAt)
			}
			return false
		})
		boundedAuthAttempts.Cleanup(func(key string, value interface{}) bool {
			if a, ok := value.(*AuthAttempt); ok {
				return time.Since(a.LastAttempt) > 1*time.Hour
			}
			return false
		})
		boundedUserQuotas.Cleanup(func(key string, value interface{}) bool {
			if q, ok := value.(*UserQuota); ok {
				return time.Since(q.LastReset) > 24*time.Hour
			}
			return false
		})
		for _, bm := range boundedRateLimitEntries {
			bm.Cleanup(func(key string, value interface{}) bool {
				if e, ok := value.(*RateLimitEntry); ok {
					return time.Since(e.LastRequest) > 24*time.Hour
				}
				return false
			})
		}
		boundedOngoingAttacks.Cleanup(func(key string, value interface{}) bool {
			if a, ok := value.(Attack); ok {
				return time.Since(a.start) > a.duration
			}
			return false
		})
		boundedOngoingAPIAttacks.Cleanup(func(key string, value interface{}) bool {
			if a, ok := value.(Attack); ok {
				return time.Since(a.start) > a.duration
			}
			return false
		})

		// Cleanup BoundedSlice
		boundedAttackHistory.Cleanup(func(value interface{}) bool {
			// Example: remove history older than 7 days
			if a, ok := value.(Attack); ok {
				return time.Since(a.start) > 7*24*time.Hour
			}
			return false
		})

		// Force GC to reclaim memory
		runtime.GC()
	}
}
