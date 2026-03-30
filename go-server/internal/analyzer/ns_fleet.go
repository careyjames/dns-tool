// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

const (
	mapKeyASName = "as_name"
	mapKeyPrefix = "prefix"
)

type NSFleetEntry struct {
	Hostname    string   `json:"hostname"`
	IPv4        []string `json:"ipv4"`
	IPv6        []string `json:"ipv6"`
	ASN         string   `json:"asn"`
	ASName      string   `json:"as_name"`
	Prefix      string   `json:"prefix"`
	UDPReach    bool     `json:"udp_reachable"`
	TCPReach    bool     `json:"tcp_reachable"`
	AAFlag      bool     `json:"aa_flag"`
	IsLame      bool     `json:"is_lame"`
	SOASerial   uint32   `json:"soa_serial"`
	SOASerialOK bool     `json:"soa_serial_ok"`
}

type NSFleetResult struct {
	Status          string         `json:"status"`
	Message         string         `json:"message"`
	Nameservers     []NSFleetEntry `json:"nameservers"`
	Diversity       FleetDiversity `json:"diversity"`
	SerialConsensus bool           `json:"serial_consensus"`
	Issues          []string       `json:"issues"`
}

type FleetDiversity struct {
	UniqueASNs      int      `json:"unique_asns"`
	UniqueOperators int      `json:"unique_operators"`
	UniquePrefix24s int      `json:"unique_prefix24s"`
	ASNList         []string `json:"asn_list"`
	OperatorList    []string `json:"operator_list"`
	Score           string   `json:"score"`
	ScoreDetail     string   `json:"score_detail"`
}

func (a *Analyzer) AnalyzeNSFleet(ctx context.Context, domain string) map[string]any {
	fleetCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	nsRecords := a.DNS.QueryDNS(fleetCtx, "NS", domain)
	if len(nsRecords) == 0 {
		return nsFleetToMap(NSFleetResult{
			Status:  "info",
			Message: "No NS records found for domain",
			Issues:  []string{},
		})
	}

	var hostnames []string
	for _, ns := range nsRecords {
		h := strings.ToLower(strings.TrimRight(ns, "."))
		if h != "" {
			hostnames = append(hostnames, h)
		}
	}

	entries := a.resolveFleetParallel(fleetCtx, domain, hostnames)

	diversity := scoreFleetDiversity(entries)
	serialConsensus := checkSerialConsensus(entries)
	issues := collectFleetIssues(entries, diversity, serialConsensus)

	status := "success"
	if len(issues) > 0 {
		status = "warning"
	}

	result := NSFleetResult{
		Status:          status,
		Message:         fmt.Sprintf("Analyzed %d nameserver(s) for %s", len(entries), domain),
		Nameservers:     entries,
		Diversity:       diversity,
		SerialConsensus: serialConsensus,
		Issues:          issues,
	}

	return nsFleetToMap(result)
}

func (a *Analyzer) resolveFleetParallel(ctx context.Context, domain string, hostnames []string) []NSFleetEntry {
	type indexedEntry struct {
		index int
		entry NSFleetEntry
	}

	ch := make(chan indexedEntry, len(hostnames))
	var wg sync.WaitGroup

	for i, hostname := range hostnames {
		wg.Add(1)
		go func(idx int, hn string) {
			defer wg.Done()
			entry := a.probeNameserver(ctx, domain, hn)
			ch <- indexedEntry{index: idx, entry: entry}
		}(i, hostname)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	entries := make([]NSFleetEntry, len(hostnames))
	for ie := range ch {
		entries[ie.index] = ie.entry
	}
	return entries
}

func (a *Analyzer) probeNameserver(ctx context.Context, domain, hostname string) NSFleetEntry {
	entry := NSFleetEntry{
		Hostname: hostname,
		IPv4:     []string{},
		IPv6:     []string{},
	}

	ipv4 := a.DNS.QueryDNS(ctx, "A", hostname)
	ipv6 := a.DNS.QueryDNS(ctx, "AAAA", hostname)
	if len(ipv4) > 0 {
		entry.IPv4 = ipv4
	}
	if len(ipv6) > 0 {
		entry.IPv6 = ipv6
	}

	a.populateASNInfo(ctx, &entry)

	targetIP := firstIP(entry.IPv4, entry.IPv6)
	if targetIP != "" {
		entry.UDPReach, entry.TCPReach, entry.AAFlag, entry.SOASerial = probeNSReachability(ctx, domain, targetIP)
		entry.IsLame = !entry.AAFlag && entry.UDPReach
		entry.SOASerialOK = entry.SOASerial > 0
	}

	return entry
}

func (a *Analyzer) populateASNInfo(ctx context.Context, entry *NSFleetEntry) {
	var asnInfo map[string]any
	if len(entry.IPv4) > 0 {
		asnInfo = a.lookupIPv4ASN(ctx, entry.IPv4[0])
	} else if len(entry.IPv6) > 0 {
		asnInfo = a.lookupIPv6ASN(ctx, entry.IPv6[0])
	} else {
		return
	}
	if asn, ok := asnInfo[mapKeyASN].(string); ok {
		entry.ASN = asn
	}
	if name, ok := asnInfo[mapKeyASName].(string); ok {
		entry.ASName = name
	}
	if prefix, ok := asnInfo[mapKeyPrefix].(string); ok {
		entry.Prefix = prefix
	}
}

func firstIP(ipv4, ipv6 []string) string {
	if len(ipv4) > 0 {
		return ipv4[0]
	}
	if len(ipv6) > 0 {
		return ipv6[0]
	}
	return ""
}

func probeNSReachability(ctx context.Context, domain, ip string) (udpOK, tcpOK, aaFlag bool, soaSerial uint32) {
	fqdn := dnsutil.Fqdn(domain)
	msg := dns.NewMsg(fqdn, dns.TypeSOA)
	msg.RecursionDesired = false

	client := &dns.Client{
		Transport: &dns.Transport{
			Dialer: &net.Dialer{
				Timeout: 3 * time.Second,
			},
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		},
	}

	addr := net.JoinHostPort(ip, "53")

	r, _, err := client.Exchange(ctx, msg, "udp", addr)
	if err == nil && r != nil {
		udpOK = true
		aaFlag = r.Authoritative
		soaSerial = extractSOASerial(r)
	}

	rTCP, _, errTCP := client.Exchange(ctx, msg, "tcp", addr)
	if errTCP == nil && rTCP != nil {
		tcpOK = true
		if !udpOK {
			aaFlag = rTCP.Authoritative
			soaSerial = extractSOASerial(rTCP)
		}
	}

	return
}

func extractSOASerial(msg *dns.Msg) uint32 {
	for _, rr := range msg.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.SOA.Serial
		}
	}
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.SOA.Serial
		}
	}
	return 0
}

func scoreFleetDiversity(entries []NSFleetEntry) FleetDiversity {
	asnSet := make(map[string]bool)
	operatorSet := make(map[string]bool)
	prefix24Set := make(map[string]bool)

	for _, e := range entries {
		if e.ASN != "" {
			asnSet[e.ASN] = true
		}
		if e.ASName != "" {
			operatorSet[e.ASName] = true
		}
		for _, ip := range e.IPv4 {
			p := extractPrefix24(ip)
			if p != "" {
				prefix24Set[p] = true
			}
		}
	}

	var asnList []string
	for asn := range asnSet {
		asnList = append(asnList, asn)
	}
	var opList []string
	for op := range operatorSet {
		opList = append(opList, op)
	}

	d := FleetDiversity{
		UniqueASNs:      len(asnSet),
		UniqueOperators: len(operatorSet),
		UniquePrefix24s: len(prefix24Set),
		ASNList:         asnList,
		OperatorList:    opList,
	}

	d.Score, d.ScoreDetail = computeDiversityScore(d.UniqueASNs, d.UniqueOperators, d.UniquePrefix24s, len(entries))
	return d
}

func computeDiversityScore(uniqueASNs, uniqueOperators, uniquePrefixes, totalNS int) (string, string) {
	if totalNS == 0 {
		return "unknown", "No nameservers to evaluate"
	}

	if uniqueASNs >= 3 && uniqueOperators >= 2 && uniquePrefixes >= 3 {
		return "excellent", fmt.Sprintf("%d ASNs, %d operators, %d /24 prefixes across %d nameservers", uniqueASNs, uniqueOperators, uniquePrefixes, totalNS)
	}
	if uniqueASNs >= 2 && uniquePrefixes >= 2 {
		return "good", fmt.Sprintf("%d ASNs, %d /24 prefixes across %d nameservers", uniqueASNs, uniquePrefixes, totalNS)
	}
	if uniqueASNs >= 2 || uniquePrefixes >= 2 {
		return "fair", fmt.Sprintf("%d ASN(s), %d /24 prefix(es) — consider adding diversity", uniqueASNs, uniquePrefixes)
	}
	return "poor", fmt.Sprintf("All %d nameservers in a single ASN and /24 prefix — single point of failure risk", totalNS)
}

func extractPrefix24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}

func checkSerialConsensus(entries []NSFleetEntry) bool {
	var serials []uint32
	for _, e := range entries {
		if e.SOASerialOK {
			serials = append(serials, e.SOASerial)
		}
	}
	if len(serials) <= 1 {
		return true
	}
	for i := 1; i < len(serials); i++ {
		if serials[i] != serials[0] {
			return false
		}
	}
	return true
}

func detectNetworkRestriction(entries []NSFleetEntry) (resolvedCount int, networkRestricted bool) {
	allUnreachable := true
	for _, e := range entries {
		if len(e.IPv4) > 0 || len(e.IPv6) > 0 {
			resolvedCount++
			if e.UDPReach || e.TCPReach {
				allUnreachable = false
			}
		}
	}
	networkRestricted = resolvedCount > 1 && allUnreachable
	return
}

func collectPerEntryIssues(entries []NSFleetEntry, networkRestricted bool) []string {
	var issues []string
	for _, e := range entries {
		if len(e.IPv4) == 0 && len(e.IPv6) == 0 {
			issues = append(issues, fmt.Sprintf("%s: no IP addresses resolved", e.Hostname))
		}
		if e.IsLame {
			issues = append(issues, fmt.Sprintf("%s: lame delegation — responds but not authoritative (no AA flag)", e.Hostname))
		}
		if networkRestricted {
			continue
		}
		hasIP := len(e.IPv4) > 0 || len(e.IPv6) > 0
		if !e.UDPReach && hasIP {
			issues = append(issues, fmt.Sprintf("%s: UDP unreachable on port 53", e.Hostname))
		}
		if !e.TCPReach && hasIP {
			issues = append(issues, fmt.Sprintf("%s: TCP unreachable on port 53", e.Hostname))
		}
	}
	return issues
}

func collectSerialInconsistencyIssues(entries []NSFleetEntry) []string {
	serialMap := make(map[uint32][]string)
	for _, e := range entries {
		if e.SOASerialOK {
			serialMap[e.SOASerial] = append(serialMap[e.SOASerial], e.Hostname)
		}
	}
	var issues []string
	for serial, hosts := range serialMap {
		issues = append(issues, fmt.Sprintf("SOA serial %d on: %s", serial, strings.Join(hosts, ", ")))
	}
	return issues
}

func collectFleetIssues(entries []NSFleetEntry, diversity FleetDiversity, serialConsensus bool) []string {
	resolvedCount, networkRestricted := detectNetworkRestriction(entries)

	issues := collectPerEntryIssues(entries, networkRestricted)

	if networkRestricted {
		issues = append(issues, fmt.Sprintf("Reachability probes skipped — all %d resolved nameservers failed both UDP and TCP, indicating the scanning environment's network restricts outbound DNS on port 53", resolvedCount))
	}

	if !serialConsensus {
		issues = append(issues, collectSerialInconsistencyIssues(entries)...)
	}

	if diversity.Score == "poor" {
		issues = append(issues, "Low nameserver diversity — all nameservers in a single ASN/prefix")
	}

	return issues
}

func nsFleetToMap(result NSFleetResult) map[string]any {
	nsEntries := make([]map[string]any, len(result.Nameservers))
	for i, e := range result.Nameservers {
		nsEntries[i] = map[string]any{
			"hostname":      e.Hostname,
			"ipv4":          e.IPv4,
			"ipv6":          e.IPv6,
			mapKeyASN:       e.ASN,
			mapKeyASName:    e.ASName,
			mapKeyPrefix:    e.Prefix,
			"udp_reachable": e.UDPReach,
			"tcp_reachable": e.TCPReach,
			"aa_flag":       e.AAFlag,
			"is_lame":       e.IsLame,
			"soa_serial":    e.SOASerial,
			"soa_serial_ok": e.SOASerialOK,
		}
	}

	return map[string]any{
		"status":           result.Status,
		"message":          result.Message,
		"nameservers":      nsEntries,
		"serial_consensus": result.SerialConsensus,
		"issues":           result.Issues,
		"diversity": map[string]any{
			"unique_asns":      result.Diversity.UniqueASNs,
			"unique_operators": result.Diversity.UniqueOperators,
			"unique_prefix24s": result.Diversity.UniquePrefix24s,
			"asn_list":         result.Diversity.ASNList,
			"operator_list":    result.Diversity.OperatorList,
			"score":            result.Diversity.Score,
			"score_detail":     result.Diversity.ScoreDetail,
		},
	}
}
