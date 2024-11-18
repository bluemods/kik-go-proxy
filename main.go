package main

import (
	"bufio"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/bluemods/kik-go-proxy/constants"
	"github.com/bluemods/kik-go-proxy/plugins"
	"github.com/bluemods/kik-go-proxy/server"
	"golang.org/x/crypto/pkcs12"
)

func main() {
	port := flag.Int("port", -1, "Port to listen for incoming connections on")
	certFile := flag.String("cert", "", "certificate PEM file, must be used with -key")
	keyFile := flag.String("key", "", "key PEM file, must be used with -cert")
	p12File := flag.String("p12", "", ".p12 certificate file, must be used with -p12-pass")
	p12PasswordFile := flag.String("p12-pass", "", "file containing the .p12 certificate password, must be used with -p12")
	ipFile := flag.String("i", "", "file containing list of interface IPs, one per line")
	iname := flag.String("iname", "", "the interface name to use, only used with -i")
	apiKeyFile := flag.String("a", "", "file containing the API key that all clients must authenticate with (using x-api-key attribute in <k header)")
	whitelistFile := flag.String("whitelist", "", "file containing JIDs / device IDs that do not require API key authentication, one per line")
	banHosts := flag.Bool("ban", false, "if true, misbehaving clients are IP banned from the server using iptables")
	antiSpamFlag := flag.Bool("spam", false, "if true, incoming spam will be intercepted and blocked")
	customBannerFlag := flag.Bool("banner", false, "if true, the server sends back a 'server' header upon successful authentication")
	enablePluginsFlag := flag.Bool("plugin", false, "if true, plugins are enabled (see plugin_registry.go)")
	flag.Parse()

	var c *server.ServerConfig
	// Is this a plain or SSL server?
	if *p12File != "" && *p12PasswordFile != "" {
		cert, err := loadP12Cert(*p12File, *p12PasswordFile)
		if err != nil {
			log.Fatal("Error loading .p12 certificate:", err.Error())
		}
		if *port == -1 {
			*port = constants.SSL_SERVER_PORT
		}
		log.Println("Certificate expires:", cert.Leaf.NotAfter)
		c = server.NewTLS(*port, &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   constants.SERVER_TLS_VERSION,
		})
	} else if *certFile != "" && *keyFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatal("Error loading key pair: ", err.Error())
		}
		if *port == -1 {
			*port = constants.SSL_SERVER_PORT
		}
		log.Println("Certificate expires:", cert.Leaf.NotAfter)
		c = server.NewTLS(*port, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   constants.SERVER_TLS_VERSION,
		})
	} else {
		if *port == -1 {
			*port = constants.PLAIN_SERVER_PORT
		}
		c = server.NewInsecure(*port)
	}

	// Are we using a custom interface to listen on?
	if *iname != "" {
		i, err := net.InterfaceByName(*iname)
		if err != nil {
			ifaces, err := net.Interfaces()
			if err != nil {
				log.Fatal(err)
			}
			msg := "Missing interface, we can select from: "
			for _, s := range ifaces {
				msg += s.Name + ","
			}
			log.Fatal(msg + " | " + err.Error())
		}
		log.Println("Using custom interface name " + *iname)

		// Interface IPs
		var interfaceIps []string
		if *ipFile != "" {
			interfaceIps, err = parseDelimitedFile(*ipFile)
			if err != nil {
				log.Fatal("failed to parse interface IPs", err)
			}
		}
		c.WithInterface(*i, interfaceIps)
	}

	// Are we using a API master key?
	if *apiKeyFile != "" {
		b, err := os.ReadFile(*apiKeyFile)
		if err != nil {
			log.Fatal("Failed parsing API key file", err.Error())
		}
		apiKey := strings.Trim(string(b), " \r\n")
		if !constants.API_KEY_REGEX.MatchString(apiKey) {
			log.Fatal(fmt.Errorf("API key at %s doesn't match regex `%s`", *apiKeyFile, constants.API_KEY_REGEX.String()))
		}
		log.Printf("API key set (length=%d)\n", len(apiKey))
		c.WithApiKey(apiKey)
	}

	// Whitelist
	if *whitelistFile != "" {
		whitelist, err := parseDelimitedFile(*whitelistFile)
		if err != nil {
			log.Fatal("failed to parse whitelist", err)
		}
		c.WithWhitelist(whitelist)
	}

	// Everything else last
	if *banHosts {
		c.WithBanHosts()
	}
	if *antiSpamFlag {
		c.WithAntiSpam()
	}
	if *customBannerFlag {
		c.WithCustomBanner()
	}
	if *enablePluginsFlag {
		if plugins.Interceptor == nil {
			log.Fatal("plugin flag specified but no plugins registered")
		}
		c.WithCustomDialer(plugins.Interceptor.Dial)
		c.WithInitStreamTagGenerator(plugins.Interceptor.MakeStreamInitTag)
		log.Println("Plugin registered (" + reflect.TypeOf(plugins.Interceptor).String() + ")")
	}
	c.Start().Await()
}

func loadP12Cert(p12File string, p12PasswordFile string) (*tls.Certificate, error) {
	p12Bytes, err := os.ReadFile(p12File)
	if err != nil {
		return nil, err
	}
	p12Password, err := os.ReadFile(p12PasswordFile)
	if err != nil {
		return nil, err
	}
	// This way supports more p12 certs, as not all of them
	// will have exactly two safe bags in the PFX PDU
	blocks, err := pkcs12.ToPEM(p12Bytes, string(p12Password))
	// Explicitly zero the password array
	for i := range p12Password {
		p12Password[i] = 0
	}
	if err != nil {
		return nil, err
	}

	var pemData []byte
	for _, block := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}
	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func parseDelimitedFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lines := []string{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), " ")

		// This allows us to include comments like
		// your_value # comment here
		i := strings.Index(line, "#")
		if i != -1 {
			line = line[:i]
		}
		lines = append(lines, strings.Trim(line, " "))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
