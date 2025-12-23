package main

import (
	"bufio"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
)

var (
	cnIPv6Nets    []*net.IPNet
	cnIPv6ISPNets []*net.IPNet
	cnIPv4Nets    []*net.IPNet
	cnIPv4ISPNets []*net.IPNet
)

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

// 判断 IPv6 是否在允许网段
func isAllowedIPv6(ip net.IP) bool {
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return false
	}
	return isInIPNets(ip, cnIPv6Nets)
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

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	primaryDNS := "119.29.29.29:53"
	fallbackDNS := "1.1.1.1:53"

	resp, err := queryDNS(r, primaryDNS)
	if err != nil {
		log.Printf("primary DNS failed: %v, fallback\n", err)
		resp, _ = queryDNS(r, fallbackDNS)
		w.WriteMsg(resp)
		return
	}

	hasAAAA := false
	ipv6Allowed := true

	for _, ans := range resp.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			hasAAAA = true
			if !isAllowedIPv6(aaaa.AAAA) {
				ipv6Allowed = false
				break
			}
		}
	}

	// 无 IPv6 或 IPv6 不在允许列表 → fallback
	if !hasAAAA || !ipv6Allowed {
		log.Printf("IPv6 missing or not allowed, fallback to 1.1.1.1")
		resp, _ = queryDNS(r, fallbackDNS)
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
