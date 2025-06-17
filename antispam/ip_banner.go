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
	ipv4Regex = regexp.MustCompile(
		`^((25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9])\.` +
			`(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.` +
			`(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.` +
			`(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[0-9]))$`)

	// Holds a set of IPs that are banned
	// or in the process of being banned.
	// Field is thread safe.
	bannedIps = utils.NewConcurrentSet[uint32]()

	// Name of the ipset that this client manages and adds IPs to.
	ipSetList     = "kik_proxy_ban_list"
	ipSetHashSize = "262144"
	ipSetMaxElem  = "524288"

	supportsIpSet    = false
	supportsIpTables = false
)

// Set up ipset if available
// install it with `sudo apt install ipset`
func init() {
	if _, err := exec.LookPath("iptables"); err != nil {
		log.Println("Server doesn't have 'iptables' installed, IP ban won't work:", err)
		return
	}
	supportsIpTables = true

	if _, err := exec.LookPath("ipset"); err != nil {
		log.Println("Server doesn't have 'ipset' installed, falling back to iptables:", err)
		return
	}

	err := exec.Command("ipset", "list", ipSetList).Run()
	if err == nil {
		// ipset previously set up, check if ipset is registered in iptables with -c flag.
		// Returns status code 0 if setup.
		if _, err := exec.Command("iptables", "-C", "INPUT", "-m", "set", "--match-set", ipSetList, "src", "-j", "DROP").Output(); err == nil {
			log.Println("iptables / ipset previously set up")
			supportsIpSet = true
		}
		return
	}

	e, ok := err.(*exec.ExitError)
	if !ok || e.ExitCode() != 1 {
		log.Println("Server doesn't have 'ipset' installed, falling back to iptables:", err)
		return
	}

	// Create ipset IP hashtable
	if stdout, err := exec.Command("ipset", "create", ipSetList, "hash:ip", "maxelem", ipSetMaxElem, "hashsize", ipSetHashSize).Output(); err != nil {
		log.Println("ipset create failed:", string(stdout), err)
		return
	}

	// Tell iptables to use our newly created ipset as a ban list source
	exec.Command("iptables", "-A", "INPUT", "-m", "set", "--match-set", ipSetList, "src", "-j", "DROP").Output()

	log.Println("ipset and iptables rules created")
	supportsIpSet = true
}

// This is a no-op if the client has an IPV6 address.
// Rewrite the method if the server is changed to accept IPV6 connections.
func BanIpAddress(ip string) {
	if !supportsIpTables {
		log.Printf("Can't ban IP %s; iptables not installed\n", ip)
		return
	}
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

	var stdout []byte

	if supportsIpSet {
		stdout, err = exec.Command("ipset", "add", ipSetList, ip).Output()
	} else {
		stdout, err = exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP").Output()
	}
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
