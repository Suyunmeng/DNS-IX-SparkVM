package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	interfaceRules []dnsInterfaceRule
)

const (
	configPath            = "config.json"
	interface12Upstream   = "119.29.29.29:53"
	interface3Upstream    = "1.1.1.1:53"
	interface3ECSUpstream = "8.8.8.8:53"
)

type appConfig struct {
	Interface1IPv4  bool   `json:"interface-1-ipv4"`
	Interface1IPv6  bool   `json:"interface-1-ipv6"`
	Interface2IPv4  bool   `json:"interface-2-ipv4"`
	Interface2IPv6  bool   `json:"interface-2-ipv6"`
	Interface3IPv4  bool   `json:"interface-3-ipv4"`
	Interface3IPv6  bool   `json:"interface-3-ipv6"`
	Interface1ECSIP string `json:"interface-1-ecsip"`
	Interface2ECSIP string `json:"interface-2-ecsip"`
	Interface3ECSIP string `json:"interface-3-ecsip"`
	Interface1IPs   string `json:"interface-1-ips"`
	Interface2IPs   string `json:"interface-2-ips"`
}

type dnsInterfaceRule struct {
	Name       string
	EnableIPv4 bool
	EnableIPv6 bool
	ECSIP      string
	Upstream   string
	MatchNets  []*net.IPNet
	NeedMatch  bool
	UseECS     bool
}

type ipQueryResult struct {
	ipv4Resp    *dns.Msg
	ipv6Resp    *dns.Msg
	ipv4Records []dns.RR
	ipv6Records []dns.RR
}

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

func loadConfig(path string) (*appConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil, fmt.Errorf("%s is empty", path)
	}

	var cfg appConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateConfig(cfg *appConfig) error {
	cfg.Interface1ECSIP = strings.TrimSpace(cfg.Interface1ECSIP)
	cfg.Interface2ECSIP = strings.TrimSpace(cfg.Interface2ECSIP)
	cfg.Interface3ECSIP = strings.TrimSpace(cfg.Interface3ECSIP)
	cfg.Interface1IPs = strings.TrimSpace(cfg.Interface1IPs)
	cfg.Interface2IPs = strings.TrimSpace(cfg.Interface2IPs)

	if err := validateECSIP(cfg.Interface1ECSIP, true, "interface-1-ecsip"); err != nil {
		return err
	}
	if err := validateECSIP(cfg.Interface2ECSIP, true, "interface-2-ecsip"); err != nil {
		return err
	}
	if err := validateECSIP(cfg.Interface3ECSIP, false, "interface-3-ecsip"); err != nil {
		return err
	}

	if cfg.Interface1IPs == "" && (cfg.Interface1IPv4 || cfg.Interface1IPv6) {
		return fmt.Errorf("interface-1-ips is required when interface-1 IPv4 or IPv6 is enabled")
	}
	if cfg.Interface2IPs == "" && (cfg.Interface2IPv4 || cfg.Interface2IPv6) {
		return fmt.Errorf("interface-2-ips is required when interface-2 IPv4 or IPv6 is enabled")
	}

	if !cfg.Interface3IPv4 && !cfg.Interface3IPv6 {
		return fmt.Errorf("interface-3-ipv4 and interface-3-ipv6 cannot both be false")
	}

	return nil
}

func validateECSIP(value string, required bool, field string) error {
	if value == "" {
		if required {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	if net.ParseIP(value) == nil {
		return fmt.Errorf("%s must be a valid IPv4 or IPv6 address", field)
	}
	return nil
}

func buildInterfaceRules(cfg *appConfig) ([]dnsInterfaceRule, error) {
	interface1Nets, err := loadInterfaceNets(cfg.Interface1IPs, cfg.Interface1IPv4 || cfg.Interface1IPv6)
	if err != nil {
		return nil, fmt.Errorf("load interface-1-ips failed: %w", err)
	}

	interface2Nets, err := loadInterfaceNets(cfg.Interface2IPs, cfg.Interface2IPv4 || cfg.Interface2IPv6)
	if err != nil {
		return nil, fmt.Errorf("load interface-2-ips failed: %w", err)
	}

	rules := []dnsInterfaceRule{
		{
			Name:       "interface-1",
			EnableIPv4: cfg.Interface1IPv4,
			EnableIPv6: cfg.Interface1IPv6,
			ECSIP:      cfg.Interface1ECSIP,
			Upstream:   interface12Upstream,
			MatchNets:  interface1Nets,
			NeedMatch:  true,
			UseECS:     true,
		},
		{
			Name:       "interface-2",
			EnableIPv4: cfg.Interface2IPv4,
			EnableIPv6: cfg.Interface2IPv6,
			ECSIP:      cfg.Interface2ECSIP,
			Upstream:   interface12Upstream,
			MatchNets:  interface2Nets,
			NeedMatch:  true,
			UseECS:     true,
		},
		{
			Name:       "interface-3",
			EnableIPv4: cfg.Interface3IPv4,
			EnableIPv6: cfg.Interface3IPv6,
			ECSIP:      cfg.Interface3ECSIP,
			Upstream:   interface3Upstream,
			NeedMatch:  false,
			UseECS:     cfg.Interface3ECSIP != "",
		},
	}

	if rules[2].UseECS {
		rules[2].Upstream = interface3ECSUpstream
	}

	return rules, nil
}

func loadInterfaceNets(path string, required bool) ([]*net.IPNet, error) {
	if !required {
		return nil, nil
	}
	nets, err := loadIPList(path)
	if err != nil {
		return nil, err
	}
	if len(nets) == 0 {
		return nil, fmt.Errorf("no valid CIDR entries found in %s", path)
	}
	return nets, nil
}

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
		Net:     "udp",
		Timeout: 3 * time.Second,
	}
	resp, _, err := c.Exchange(r, server)
	return resp, err
}

// Query DNS with EDNS Client Subnet
func queryDNSWithEDNS(r *dns.Msg, server string, clientSubnet string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Create a copy to avoid modifying the original request
	req := r.Copy()

	// Remove any existing EDNS0 records
	req.Extra = nil

	maskedIP, family, sourceNetmask, err := getMaskedECSIP(clientSubnet)
	if err != nil {
		return nil, err
	}

	// Create EDNS0 subnet option
	e := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: sourceNetmask,
		SourceScope:   0,
		Address:       maskedIP,
	}

	// Set EDNS0 using the SetEdns0 method
	req.SetEdns0(4096, false)

	// Add the subnet option to the OPT record
	if opt := req.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, e)
	} else {
		return nil, fmt.Errorf("failed to create EDNS OPT record")
	}

	// Retry mechanism: try up to 3 times
	var resp *dns.Msg
	err = nil
	for i := 0; i < 3; i++ {
		resp, _, err = c.Exchange(req, server)
		if err == nil {
			return resp, nil
		}
		if i < 2 {
			log.Printf("EDNS query attempt %d failed: %v, retrying...", i+1, err)
			time.Sleep(500 * time.Millisecond)
		}
	}
	return nil, err
}

func getMaskedECSIP(value string) (net.IP, uint16, uint8, error) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return nil, 0, 0, fmt.Errorf("invalid ECS IP: %s", value)
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		mask := net.CIDRMask(24, 32)
		return ipv4.Mask(mask), 1, 24, nil
	}

	ipv6 := ip.To16()
	if ipv6 == nil {
		return nil, 0, 0, fmt.Errorf("invalid ECS IP: %s", value)
	}
	mask := net.CIDRMask(96, 128)
	return ipv6.Mask(mask), 2, 96, nil
}

func queryByRule(r *dns.Msg, rule dnsInterfaceRule) (*dns.Msg, error) {
	if rule.UseECS {
		return queryDNSWithEDNS(r, rule.Upstream, rule.ECSIP)
	}
	return queryDNS(r, rule.Upstream)
}

func queryQTypeByRule(r *dns.Msg, qType uint16, rule dnsInterfaceRule) (*dns.Msg, error) {
	req := r.Copy()
	if len(req.Question) == 0 {
		return nil, fmt.Errorf("empty DNS question")
	}
	req.Question[0].Qtype = qType
	return queryByRule(req, rule)
}

func queryIPRecords(r *dns.Msg, rule dnsInterfaceRule) (*ipQueryResult, error) {
	result := &ipQueryResult{}
	var errs []string

	if rule.EnableIPv4 {
		resp, err := queryQTypeByRule(r, dns.TypeA, rule)
		if err != nil {
			errs = append(errs, fmt.Sprintf("A query failed: %v", err))
		} else {
			result.ipv4Resp = resp
			result.ipv4Records = extractRecordsByType(resp, dns.TypeA)
		}
	}

	if rule.EnableIPv6 {
		resp, err := queryQTypeByRule(r, dns.TypeAAAA, rule)
		if err != nil {
			errs = append(errs, fmt.Sprintf("AAAA query failed: %v", err))
		} else {
			result.ipv6Resp = resp
			result.ipv6Records = extractRecordsByType(resp, dns.TypeAAAA)
		}
	}

	if result.ipv4Resp == nil && result.ipv6Resp == nil {
		if len(errs) == 0 {
			return nil, fmt.Errorf("no DNS query executed for %s", rule.Name)
		}
		return nil, fmt.Errorf(strings.Join(errs, "; "))
	}

	return result, nil
}

func extractRecordsByType(resp *dns.Msg, qType uint16) []dns.RR {
	if resp == nil {
		return nil
	}

	var records []dns.RR
	for _, ans := range resp.Answer {
		switch qType {
		case dns.TypeA:
			if _, ok := ans.(*dns.A); ok {
				records = append(records, ans)
			}
		case dns.TypeAAAA:
			if _, ok := ans.(*dns.AAAA); ok {
				records = append(records, ans)
			}
		}
	}
	return records
}

func filterRecordsByNets(records []dns.RR, nets []*net.IPNet) []dns.RR {
	var filtered []dns.RR
	for _, rr := range records {
		switch v := rr.(type) {
		case *dns.A:
			if isInIPNets(v.A, nets) {
				filtered = append(filtered, rr)
			}
		case *dns.AAAA:
			if isInIPNets(v.AAAA, nets) {
				filtered = append(filtered, rr)
			}
		}
	}
	return filtered
}

func buildResponse(r *dns.Msg, result *ipQueryResult, ipv4Records []dns.RR, ipv6Records []dns.RR) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(r)

	source := pickSourceResponse(r, result)
	if source != nil {
		resp.Rcode = source.Rcode
		resp.RecursionAvailable = source.RecursionAvailable
		resp.Authoritative = source.Authoritative
		resp.AuthenticatedData = source.AuthenticatedData
		resp.CheckingDisabled = source.CheckingDisabled
		resp.Ns = append(resp.Ns, source.Ns...)
	}

	resp.Answer = appendUniqueRR(resp.Answer, collectCNAMERecords(result))
	resp.Answer = appendUniqueRR(resp.Answer, ipv4Records)
	resp.Answer = appendUniqueRR(resp.Answer, ipv6Records)
	return resp
}

func pickSourceResponse(r *dns.Msg, result *ipQueryResult) *dns.Msg {
	if len(r.Question) == 0 {
		if result.ipv4Resp != nil {
			return result.ipv4Resp
		}
		return result.ipv6Resp
	}

	switch r.Question[0].Qtype {
	case dns.TypeAAAA:
		if result.ipv6Resp != nil {
			return result.ipv6Resp
		}
		return result.ipv4Resp
	default:
		if result.ipv4Resp != nil {
			return result.ipv4Resp
		}
		return result.ipv6Resp
	}
}

func collectCNAMERecords(result *ipQueryResult) []dns.RR {
	seen := make(map[string]struct{})
	var cnameRecords []dns.RR

	responses := []*dns.Msg{result.ipv4Resp, result.ipv6Resp}
	for _, msg := range responses {
		if msg == nil {
			continue
		}
		for _, ans := range msg.Answer {
			if _, ok := ans.(*dns.CNAME); !ok {
				continue
			}
			key := ans.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			cnameRecords = append(cnameRecords, ans)
		}
	}

	return cnameRecords
}

func appendUniqueRR(dst []dns.RR, src []dns.RR) []dns.RR {
	seen := make(map[string]struct{}, len(dst))
	for _, rr := range dst {
		seen[rr.String()] = struct{}{}
	}

	for _, rr := range src {
		key := rr.String()
		if _, exists := seen[key]; exists {
			continue
		}
		dst = append(dst, rr)
		seen[key] = struct{}{}
	}

	return dst
}

func evaluateIPRule(r *dns.Msg, rule dnsInterfaceRule) (*dns.Msg, bool, error) {
	queryResult, err := queryIPRecords(r, rule)
	if err != nil {
		return nil, false, err
	}

	if rule.NeedMatch {
		var matchedIPv4 []dns.RR
		var matchedIPv6 []dns.RR

		if rule.EnableIPv4 {
			matchedIPv4 = filterRecordsByNets(queryResult.ipv4Records, rule.MatchNets)
		}
		if rule.EnableIPv6 {
			matchedIPv6 = filterRecordsByNets(queryResult.ipv6Records, rule.MatchNets)
		}

		if len(matchedIPv4) == 0 && len(matchedIPv6) == 0 {
			return nil, false, nil
		}
		return buildResponse(r, queryResult, matchedIPv4, matchedIPv6), true, nil
	}

	return buildResponse(r, queryResult, queryResult.ipv4Records, queryResult.ipv6Records), true, nil
}

func resolveIPQuery(r *dns.Msg) (*dns.Msg, error) {
	for _, rule := range interfaceRules {
		if !rule.EnableIPv4 && !rule.EnableIPv6 {
			log.Printf("%s skipped: IPv4 and IPv6 are both disabled", rule.Name)
			continue
		}

		resp, matched, err := evaluateIPRule(r, rule)
		if err != nil {
			log.Printf("%s query failed: %v", rule.Name, err)
			continue
		}
		if !matched {
			log.Printf("%s no match, fallback to next interface", rule.Name)
			continue
		}

		log.Printf("%s matched and selected", rule.Name)
		return resp, nil
	}

	return nil, fmt.Errorf("no available interface produced response")
}

func resolveNonIPQuery(r *dns.Msg) (*dns.Msg, error) {
	for _, rule := range interfaceRules {
		if !rule.EnableIPv4 && !rule.EnableIPv6 {
			continue
		}
		resp, err := queryByRule(r, rule)
		if err != nil {
			log.Printf("%s non-IP query failed: %v", rule.Name, err)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("no upstream available for non-IP query")
}

func resolveQuery(r *dns.Msg) (*dns.Msg, error) {
	if len(r.Question) == 0 {
		return nil, fmt.Errorf("empty DNS question")
	}

	qType := r.Question[0].Qtype
	if qType == dns.TypeA || qType == dns.TypeAAAA {
		return resolveIPQuery(r)
	}
	return resolveNonIPQuery(r)
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
	if len(r.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(resp)
		return
	}

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

	resp, err := resolveQuery(r)
	if err != nil || resp == nil {
		log.Printf("resolve query failed: %v", err)
		fail := new(dns.Msg)
		fail.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(fail)
		return
	}

	if cacheKey != "" {
		cache.Set(cacheKey, resp, getMinTTL(resp))
	}
	resp.Id = r.Id
	w.WriteMsg(resp)
}

func main() {
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load %s: %v", configPath, err)
	}

	interfaceRules, err = buildInterfaceRules(cfg)
	if err != nil {
		log.Fatalf("failed to build interface rules: %v", err)
	}

	for _, rule := range interfaceRules {
		log.Printf("%s enabled: ipv4=%t ipv6=%t upstream=%s useECS=%t", rule.Name, rule.EnableIPv4, rule.EnableIPv6, rule.Upstream, rule.UseECS)
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
			Addr: ":5353",
			Net:  "udp",
		}
		log.Println("DNS server started on UDP :5353")
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("UDP server failed: %v", err)
		}
	}()

	// TCP
	server := &dns.Server{
		Addr: ":5353",
		Net:  "tcp",
	}
	log.Println("DNS server started on TCP :5353")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("TCP server failed: %v", err)
	}
}
