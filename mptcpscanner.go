/*
Copyright 2013-2014 Graham King

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

For full license details see <http://www.gnu.org/licenses/>.
*/

package main

import (
	//"cmd/go/internal/version"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	helpParam   = flag.Bool("h", false, "Print help")
	ifaceParam  = flag.String("i", "", "Interface (e.g. eth0, wlan1, etc)")
	countParam  = flag.Int("c", 100, "The count of sites need to scan")
	fileParam   = flag.String("f", "", "The file path of the site list")
	outputParam = flag.String("o", "", "The flie path of output result")
)

func main() {
	flag.Parse()

	if *helpParam {
		printHelp()
		os.Exit(1)
	}

	iface := *ifaceParam
	if iface == "" {
		iface = chooseInterface()
		if iface == "" {
			fmt.Println("Could not decide which net interface to use.")
			fmt.Println("Specify it with -i <iface> param")
			os.Exit(1)
		}
	}

	if *fileParam == "" {
		fmt.Println("Missing host list file path.")
		os.Exit(1)
	}

	if *outputParam == "" {
		fmt.Println("Missing output file path.")
		os.Exit(1)
	}

	localAddr := interfaceAddress(iface)
	laddr := strings.Split(localAddr.String(), "/")[0] // Clean addresses like 192.168.1.30/24

	autoTest(laddr)
	return

}

func autoTest(localAddr string) {
	filePath := *fileParam
	count := *countParam

	f, err := os.Open(filePath)
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}

	rd := bufio.NewReader(f)

	results := make([]Result, count)

	//for i, host := range defaultHosts {
	for i := 0; i < count; i++ {
		line, _, _ := rd.ReadLine()
		host := strings.Split(string(line), ",")[1]
		result := latency(localAddr, host)
		results[i] = result
		//fmt.Printf("== %v: %v\n", host, duration)
	}

	data, _ := json.Marshal(results)

	err = ioutil.WriteFile(*outputParam, data, 0644)
	//fmt.Println(string(jsonString))
}

var ports = []uint16{80, 443}
var versions = []uint8{0, 1}

func latency(localAddr string, remoteHost string) Result {
	addrs, err := net.LookupHost(remoteHost)
	var result Result
	result.Host = remoteHost
	if err != nil {
		return result
	}
	remoteAddr := addrs[0]
	fmt.Printf("= %v <==> %v", remoteHost, remoteAddr)
	result.Address = remoteAddr
	result.PortResults = make([]PortResult, 2) //[2]PortResult{}

	d := net.Dialer{Timeout: time.Duration(2) * time.Second}
	for i, port := range ports {
		var portResult = &result.PortResults[i]
		portResult.Port = port

		var remoteaddr = fmt.Sprintf("%s:%d", remoteAddr, port)
		conn, err := d.Dial("tcp", remoteaddr)
		if conn != nil {
			conn.Close()
		}
		if err != nil {
			fmt.Printf(" %v unconnected \n", port)
			continue
		}
		if i == 0 {
			fmt.Println()
		}

		portResult.TCPConnectable = true
		portResult.MPTCPResults = make([]MPTCPResult, 2) //[2]MPTCPResult{}

		for j, version := range versions {
			duration, result := sendSyn(localAddr, remoteAddr, port, version)
			fmt.Printf("== %v\n", duration)
			portResult.MPTCPResults[j] = result
		}
	}

	return result
	// wg.Wait()
	// return receiveTime.Sub(sendTime)
}

func chooseInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("net.Interfaces: %s", err)
	}
	for _, iface := range interfaces {
		// Skip loopback
		if iface.Name == "lo" {
			continue
		}
		addrs, err := iface.Addrs()
		// Skip if error getting addresses
		if err != nil {
			log.Printf("Error get addresses for interfaces %s. %s\n", iface.Name, err)
			continue
		}

		if len(addrs) > 0 {
			// This one will do
			return iface.Name
		}
	}

	return ""
}

func interfaceAddress(ifaceName string) net.Addr {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("net.InterfaceByName for %s. %s", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("iface.Addrs: %s", err)
	}
	return addrs[0]
}

func printHelp() {
	// help := `
	// USAGE: latency [-h] [-a] [-i iface] [-p port] <remote>
	// Where 'remote' is an ip address or host name.
	// Default port is 80
	// -h: Help
	// -a: Run auto test against several well known sites
	// `
	// fmt.Println(help)
	flag.Usage()
}

func sendSyn(laddr, raddr string, port uint16, version uint8) (time.Duration, MPTCPResult) {
	option := TCPOption{
		Kind: 30, Length: 12, SubType: 0, Version: version, A: 1, B: 0, C: 0, H: 1, SenderKey: rand.Uint64(),
	}
	packet := TCPHeader{
		Source:      0xaa47, // Random ephemeral port
		Destination: port,
		SeqNum:      rand.Uint32(),
		AckNum:      0,
		DataOffset:  8,      // 4 bits
		Reserved:    0,      // 3 bits
		ECN:         0,      // 3 bits
		Ctrl:        2,      // 6 bits (000010, SYN bit set)
		Window:      0xaaaa, // The amount of data that it is able to accept in bytes
		Checksum:    0,      // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []TCPOption{option},
	}

	var receiveTime time.Time
	var result MPTCPResult
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		receiveTime, result = receiveSynAck(laddr, raddr, packet.Source, packet.Destination, option.SenderKey, option.Version)
		wg.Done()
	}()
	time.Sleep(1 * time.Millisecond)

	data := packet.Marshal()
	packet.Checksum = Csum(data, to4byte(laddr), to4byte(raddr))
	data = packet.Marshal()

	var dialer = &net.Dialer{
		LocalAddr: &net.IPAddr{
			IP: net.ParseIP(laddr),
		},
	}

	conn, err := dialer.Dial("ip4:tcp", raddr)
	if err != nil {
		log.Fatalf("Dial: %s\n", err)
	}

	sendTime := time.Now()

	numWrote, err := conn.Write(data)
	fmt.Printf("> IP:%v, Source:%v, Dest:%v, Options:[Kind:%v, Version:%v, SenderKey:%v]\n", raddr, packet.Source, packet.Destination, option.Kind, option.Version, option.SenderKey)

	if err != nil {
		log.Fatalf("Write: %s\n", err)
	}
	if numWrote != len(data) {
		log.Fatalf("Short write. Wrote %d/%d bytes\n", numWrote, len(data))
	}
	conn.Close()
	wg.Wait()
	return receiveTime.Sub(sendTime), result
}

func to4byte(addr string) [4]byte {
	parts := strings.Split(addr, ".")
	b0, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Fatalf("to4byte: %s (latency works with IPv4 addresses only, but not IPv6!)\n", err)
	}
	b1, _ := strconv.Atoi(parts[1])
	b2, _ := strconv.Atoi(parts[2])
	b3, _ := strconv.Atoi(parts[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

type Result struct {
	Host        string
	Address     string
	PortResults []PortResult
}

type PortResult struct {
	Port           uint16
	TCPConnectable bool
	MPTCPResults   []MPTCPResult
}

type MPTCPResult struct {
	SenderVersion   uint8
	ReceiverVersion uint8
	Flags           uint8

	NoMPTCPOption    bool
	WrongVersion     bool
	WrongReceiverKey bool
	RST              bool
	SYNACK           bool
	Timeout          bool
}

func receiveSynAck(localAddress, remoteAddress string, sourcePort, destPort uint16, senderKey uint64, version uint8) (time.Time, MPTCPResult) {
	netaddr, err := net.ResolveIPAddr("ip4", localAddress)
	if err != nil {
		log.Fatalf("net.ResolveIPAddr: %s. %s\n", localAddress, netaddr)
	}

	conn, err := net.ListenIP("ip4:tcp", netaddr)
	defer conn.Close()
	if err != nil {
		log.Fatalf("ListenIP: %s\n", err)
	}

	isTimeout := false
	timer := time.AfterFunc(time.Duration(2)*time.Second, func() {
		isTimeout = true
	})
	defer timer.Stop()

	var receiveTime time.Time
	var result MPTCPResult
	result.SenderVersion = version
	for {
		if isTimeout {
			result.Timeout = true
			break
		}
		buf := make([]byte, 1024)
		numRead, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("ReadFrom: %s\n", err)
		}
		if raddr.String() != remoteAddress {
			// this is not the packet we are looking for
			continue
		}
		//fmt.Printf("Received: % x\n", buf[:numRead])
		tcp := NewTCPHeader(buf[:numRead])

		if tcp.Source != destPort || tcp.Destination != sourcePort {
			continue
		}
		fmt.Printf("< IP:%v, Source:%v, Dest:%v, Options:", raddr, tcp.Source, tcp.Destination)

		var mptcpOption *TCPOption = nil
		for _, option := range tcp.Options {

			if option.Kind == 30 {
				mptcpOption = &option
				fmt.Printf("[Kind:%v, Length:%v, Version:%v, ReceiverKey:%v]", option.Kind, option.Length, option.Version, option.ReceiverKey)
			} else {
				fmt.Printf("[Kind:%v, Length:%v]", option.Kind, option.Length)
			}
		}
		fmt.Println()
		if mptcpOption != nil {
			result.ReceiverVersion = mptcpOption.Version
			if mptcpOption.ReceiverKey == senderKey {
				result.WrongReceiverKey = true
				// Identical Receiver and SenderKey
			}

			if mptcpOption.Version > version {
				result.WrongVersion = true
				// Wrong version
			}
		} else {
			result.NoMPTCPOption = true
			// No MPTCP Option
		}
		receiveTime = time.Now()
		result.Flags = tcp.Ctrl
		if tcp.HasFlag(SYN) && tcp.HasFlag(ACK) {
			result.SYNACK = true
			// Open the connection
		} else if tcp.HasFlag(RST) {
			result.RST = true
		}
		break
	}
	return receiveTime, result
}
