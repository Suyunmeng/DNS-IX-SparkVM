package main

import (
	"bufio"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	cnIPv6Nets    []*net.IPNet
	cnIPv6ISPNets []*net.IPNet
	cnIPv4Nets    []*net.IPNet
	cnIPv4ISPNets []*net.IPNet
)

// DNS cache entry with expiration
type cacheEntry struct {
	response  *dns.Msg
	expiresAt time.Time
}

// DNS response cache with concurrent access support
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		entries: make(map[string]*cacheEntry),
	}
}

// Get cached response if not expired
func (c *dnsCache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.response.Copy(), true
}

// Set cache entry with TTL
func (c *dnsCache) Set(key string, resp *dns.Msg, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		response:  resp.Copy(),
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// Clean expired entries
func (c *dnsCache) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

var cache = newDNSCache()

// Load IP list from file (generic loader for both IPv4 and IPv6)
func loadIPList(path string) ([]*net.IPNet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var nets []*net.IPNet
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("invalid CIDR skipped: %s\n", line)
			continue
		}
		nets = append(nets, ipNet)
	}
	return nets, scanner.Err()
}

// Check if IP is in the given network list
func isInIPNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// 查询上游 DNS
func queryDNS(r *dns.Msg, server string) (*dns.Msg, error) {
	c := &dns.Client{
		Net: "udp",
	}
	return c.Exchange(r, server)
}

// Query DNS with EDNS Client Subnet
func queryDNSWithEDNS(r *dns.Msg, server string, clientSubnet string) (*dns.Msg, error) {
	c := &dns.Client{
		Net: "udp",
	}

	// Create a copy to avoid modifying the original request
	req := r.Copy()

	// Parse the client subnet IP
	ip := net.ParseIP(clientSubnet)
	if ip == nil {
		return nil, dns.ErrId
	}

	// Determine subnet size based on IP type
	var family uint16
	var sourceNetmask uint8
	if ip.To4() != nil {
		family = 1 // IPv4
		sourceNetmask = 32
	} else {
		family = 2 // IPv6
		sourceNetmask = 128
	}

	// Create EDNS0 subnet option
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	e := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: sourceNetmask,
		SourceScope:   0,
		Address:       ip,
	}
	opt.Option = append(opt.Option, e)
	req.Extra = append(req.Extra, opt)

	return c.Exchange(req, server)
}

// Get minimum TTL from DNS response
func getMinTTL(resp *dns.Msg) uint32 {
	if resp == nil || len(resp.Answer) == 0 {
		return 300 // Default 5 minutes
	}

	minTTL := uint32(3600) // Max 1 hour
	for _, ans := range resp.Answer {
		if ans.Header().Ttl < minTTL {
			minTTL = ans.Header().Ttl
		}
	}

	// Ensure minimum TTL of 60 seconds
	if minTTL < 60 {
		minTTL = 60
	}
	return minTTL
}

// Generate cache key from DNS question
func getCacheKey(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	q := r.Question[0]
	return q.Name + ":" + dns.TypeToString[q.Qtype]
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	primaryDNS := "119.29.29.29:53"
	fallbackDNS := "1.1.1.1:53"
	ednsClientSubnet := "183.61.225.70"

	// Check cache first
	cacheKey := getCacheKey(r)
	if cacheKey != "" {
		if cachedResp, found := cache.Get(cacheKey); found {
			log.Printf("Cache hit for %s", cacheKey)
			cachedResp.Id = r.Id // Update message ID to match request
			w.WriteMsg(cachedResp)
			return
		}
	}

	// Query primary DNS first
	resp, err := queryDNS(r, primaryDNS)
	if err != nil {
		log.Printf("primary DNS failed: %v, fallback to %s\n", err, fallbackDNS)
		resp, _ = queryDNS(r, fallbackDNS)
		if resp != nil && cacheKey != "" {
			cache.Set(cacheKey, resp, getMinTTL(resp))
		}
		w.WriteMsg(resp)
		return
	}

	// Check response for IPv6 and IPv4 records
	var hasIPv6 bool
	var hasIPv4 bool
	var ipv6InCN bool
	var ipv6InISP bool
	var ipv4InCN bool
	var ipv4InISP bool

	// Optimize: check IPv6 first, early exit if found in ISP list
	for _, ans := range resp.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			hasIPv6 = true
			if isInIPNets(aaaa.AAAA, cnIPv6Nets) {
				ipv6InCN = true
				if isInIPNets(aaaa.AAAA, cnIPv6ISPNets) {
					ipv6InISP = true
				}
			}
		}
	}

	// Optimize: only check IPv4 if no IPv6 found
	if !hasIPv6 {
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				hasIPv4 = true
				if isInIPNets(a.A, cnIPv4Nets) {
					ipv4InCN = true
					if isInIPNets(a.A, cnIPv4ISPNets) {
						ipv4InISP = true
					}
				}
			}
		}
	}

	// IPv6 processing logic
	if hasIPv6 {
		if ipv6InCN {
			if ipv6InISP {
				// IPv6 in both cn-ipv6.list and cn-ipv6-isp.list
				// Re-query with EDNS and return only IPv6
				log.Printf("IPv6 in CN ISP list, re-querying with EDNS client subnet %s", ednsClientSubnet)
				ednsResp, err := queryDNSWithEDNS(r, primaryDNS, ednsClientSubnet)
				if err != nil {
					log.Printf("EDNS query failed: %v, using original response\n", err)
					w.WriteMsg(resp)
					return
				}

				// Filter response to include only IPv6 records
				filteredResp := new(dns.Msg)
				filteredResp.SetReply(r)
				for _, ans := range ednsResp.Answer {
					if _, ok := ans.(*dns.AAAA); ok {
						filteredResp.Answer = append(filteredResp.Answer, ans)
					}
				}
				if cacheKey != "" {
					cache.Set(cacheKey, filteredResp, getMinTTL(filteredResp))
				}
				w.WriteMsg(filteredResp)
				return
			}
			// IPv6 in cn-ipv6.list but not in cn-ipv6-isp.list
			// Return full response (IPv4+IPv6)
			log.Printf("IPv6 in CN list but not ISP list, returning full response")
			if cacheKey != "" {
				cache.Set(cacheKey, resp, getMinTTL(resp))
			}
			w.WriteMsg(resp)
			return
		}
		// IPv6 not in cn-ipv6.list, fallback to 1.1.1.1
		log.Printf("IPv6 not in CN list, fallback to %s", fallbackDNS)
		resp, _ = queryDNS(r, fallbackDNS)
		if resp != nil && cacheKey != "" {
			cache.Set(cacheKey, resp, getMinTTL(resp))
		}
		w.WriteMsg(resp)
		return
	}

	// Only IPv4 processing logic
	if hasIPv4 {
		if ipv4InCN {
			if ipv4InISP {
				// IPv4 in both lists, fallback to 1.1.1.1
				log.Printf("IPv4 in both CN and ISP lists, fallback to %s", fallbackDNS)
				resp, _ = queryDNS(r, fallbackDNS)
				if resp != nil && cacheKey != "" {
					cache.Set(cacheKey, resp, getMinTTL(resp))
				}
				w.WriteMsg(resp)
				return
			}
			// IPv4 in cn-ipv4.list but not in cn-ipv4-isp.list
			// Return original response
			log.Printf("IPv4 in CN list but not ISP list, returning original response")
			if cacheKey != "" {
				cache.Set(cacheKey, resp, getMinTTL(resp))
			}
			w.WriteMsg(resp)
			return
		}
	}

	// Default: return original response
	if cacheKey != "" {
		cache.Set(cacheKey, resp, getMinTTL(resp))
	}
	w.WriteMsg(resp)
}

func main() {
	var err error
	cnIPv6Nets, err = loadIPList("cn-ipv6.list")
	if err != nil {
		log.Fatalf("failed to load cn-ipv6.list: %v", err)
	}
	cnIPv6ISPNets, err = loadIPList("cn-ipv6-isp.list")
	if err != nil {
		log.Fatalf("failed to load cn-ipv6-isp.list: %v", err)
	}
	cnIPv4Nets, err = loadIPList("cn-ipv4.list")
	if err != nil {
		log.Fatalf("failed to load cn-ipv4.list: %v", err)
	}
	cnIPv4ISPNets, err = loadIPList("cn-ipv4-isp.list")
	if err != nil {
		log.Fatalf("failed to load cn-ipv4-isp.list: %v", err)
	}

	// Start cache cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cache.CleanExpired()
			log.Println("Cache cleanup completed")
		}
	}()

	dns.HandleFunc(".", handleDNS)

	// UDP
	go func() {
		server := &dns.Server{
			Addr: ":53",
			Net:  "udp",
		}
		log.Println("DNS server started on UDP :53")
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("UDP server failed: %v", err)
		}
	}()

	// TCP
	server := &dns.Server{
		Addr: ":53",
		Net:  "tcp",
	}
	log.Println("DNS server started on TCP :53")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("TCP server failed: %v", err)
	}
}
