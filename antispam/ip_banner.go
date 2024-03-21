package antispam

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os/exec"
	"regexp"

	"github.com/bluemods/kik-go-proxy/utils"
)

var (
	ipv4Regex *regexp.Regexp = regexp.MustCompile(
		`^((25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9])\.` +
			`(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.` +
			`(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.` +
			`(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[0-9]))$`)

	// Holds a set of IPs that are banned
	// or in the process of being banned.
	// Field is thread safe.
	bannedIps *utils.ConcurrentSet[uint32] = utils.NewConcurrentSet[uint32]()
)

// This is a no-op if the client has an IPV6 address.
// Rewrite the method if the server is changed to accept IPV6 connections.
func BanIpAddress(ip string) {
	if !ipv4Regex.MatchString(ip) {
		// This is ultra defensive programming
		// to make sure no bad values can be passed to the command
		log.Printf("Can't ban IP %s; doesn't match IPV4 regex\n", ip)
		return
	}
	ipInt, err := ipv4ToInt(net.ParseIP(ip))
	if err == nil && bannedIps.Add(ipInt) {
		// IP is already banned or in the process of being banned, take no action
		return
	}

	stdout, err := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP").Output()
	if err != nil {
		log.Println("Failed to ban " + ip + ": " + err.Error())
	} else {
		log.Println("Banned " + ip + ": " + string(stdout))
	}
}

func ipv4ToInt(ip net.IP) (uint32, error) {
	if ipv4 := ip.To4(); ipv4 != nil {
		return binary.BigEndian.Uint32(ipv4), nil
	}
	return 0, errors.New("not a valid IPv4 address")
}
