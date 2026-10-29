package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[91m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
	colorCyan   = "\033[96m"
	colorPurple = "\033[95m"
	colorBold   = "\033[1m"
)

func printBanner() {
	// البانر اللي طلبتي مع الألوان
	fmt.Println(colorPurple + colorBold)
	fmt.Println(`           _                           _       _               `)
	fmt.Println(`   __| |_ __  ___  __      ____ _| |_ ___| |__   ___ _ __ `)
	fmt.Println(`  / _` + "`" + ` | '_ \/ __| \ \ /\ / / _` + "`" + ` | __/ __| '_ \ / _ \ '__|`)
	fmt.Println(` | (_| | | | \__ \  \ V  V / (_| | || (__| | | |  __/ |   `)
	fmt.Println(`  \__,_|_| |_|___/   \_/\_/ \__,_|\__\___|_| |_|\___|_|   `)
	fmt.Println(colorReset)
	fmt.Println(colorCyan + "                    by K52-ai" + colorReset)
	fmt.Println("--------------------------------------------------")
}

func analyzePCAP(filepath string) {
	handle, err := pcap.OpenOffline(filepath)
	if err != nil {
		fmt.Printf("%s[-] Error opening file: %v%s\n", colorRed, err, colorReset)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	domainCounts := make(map[string]int)
	ipDomains := make(map[string]map[string]bool)
	totalDNS := 0

	fmt.Printf("%s[*] Analyzing DNS traffic from: %s%s\n", colorCyan, filepath, colorReset)
	fmt.Printf("%s[*] This might take a moment...%s\n\n", colorYellow, colorReset)

	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			for _, question := range dns.Questions {
				domain := string(question.Name)
				if domain != "" {
					totalDNS++
					domainCounts[domain]++
					
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					if ipLayer != nil {
						ip, _ := ipLayer.(*layers.IPv4)
						srcIP := ip.SrcIP.String()
						if ipDomains[domain] == nil {
							ipDomains[domain] = make(map[string]bool)
						}
						ipDomains[domain][srcIP] = true
					}
				}
			}
		}
	}

	if totalDNS == 0 {
		fmt.Printf("%s[-] No DNS traffic found in this PCAP file.%s\n", colorRed, colorReset)
		return
	}

	fmt.Printf("%s[+] Total DNS Requests Found: %d%s\n", colorGreen, totalDNS, colorReset)
	fmt.Printf("%s[+] Unique Domains Queried: %d%s\n\n", colorGreen, len(domainCounts), colorReset)

	type kv struct {
		Key   string
		Value int
	}
	var sortedDomains []kv
	for k, v := range domainCounts {
		sortedDomains = append(sortedDomains, kv{k, v})
	}
	sort.Slice(sortedDomains, func(i, j int) bool {
		return sortedDomains[i].Value > sortedDomains[j].Value
	})

	fmt.Println(colorCyan + "--------------------------------------------------" + colorReset)
	fmt.Println(colorBold + "[+] TOP DOMAINS QUERIED:" + colorReset)
	fmt.Println(colorCyan + "--------------------------------------------------" + colorReset)
	
	limit := 10
	if len(sortedDomains) < limit {
		limit = len(sortedDomains)
	}
	for i := 0; i < limit; i++ {
		fmt.Printf("  %-30s (%d requests)\n", sortedDomains[i].Key, sortedDomains[i].Value)
	}

	fmt.Println(colorCyan + "\n--------------------------------------------------" + colorReset)
	fmt.Println(colorBold + "[+] SUSPICIOUS DOMAINS (Potential DNS Tunneling):" + colorReset)
	fmt.Println(colorCyan + "--------------------------------------------------" + colorReset)

	suspiciousFound := false
	for domain, ips := range ipDomains {
		if len(domain) > 35 || strings.Count(domain, ".") > 4 {
			suspiciousFound = true
			ipList := []string{}
			for ip := range ips {
				ipList = append(ipList, ip)
			}
			fmt.Printf("%s  [!] %s (Queried by: %s)%s\n", colorRed, domain, strings.Join(ipList, ", "), colorReset)
		}
	}
	if !suspiciousFound {
		fmt.Printf("%s  No suspicious domains detected.%s\n", colorGreen, colorReset)
	}

	fmt.Println(colorCyan + "\n==================================================" + colorReset)
	fmt.Printf("%s[+] Analysis Complete.%s\n", colorGreen, colorReset)
}

func main() {
	printBanner()

	var filepath string
	if len(os.Args) > 1 {
		filepath = os.Args[1]
	} else {
		fmt.Print(colorYellow + "Enter PCAP file path: " + colorReset)
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		filepath = strings.TrimSpace(input)
	}

	if filepath == "" {
		fmt.Printf("%s[-] Error: No file path provided.%s\n", colorRed, colorReset)
		return
	}

	analyzePCAP(filepath)
}
