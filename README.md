# Kik XMPP Go Proxy

Originally written in Java, but now being ported to Go (for performance reasons and learning), this tool allows you to proxy XMPP connections from your server to another by MITMing them.
<br>
The server listens on port 5222 for plain text connections by default, and 5223 by default for SSL connections.
<br>
The server connects to Kik via port 443 by default.

Use cases for this include:
- Validating stream headers (`<k ` tags) from clients
- Intercepting / modifying packets
- Filtering incoming spam before it's sent to the client
- Improved connection stability
- Debugging traffic from the official mobile clients (stock Kik) or your custom client

## Requirements
Go >= 1.21.3 (on *nix it can be easily installed [here](https://github.com/udhos/update-golang))

## Install, build and run

```bash
git clone https://github.com/bluemods/kik-go-proxy && cd kik-go-proxy
```
```bash
go mod tidy && go build && ./kik-go-proxy
```

## Arguments
Note: If you use `-cert -key` or `-p12 -p12-pass` flag pairs, the program will use them to open an encrypted (SSL) connection. 
The `-cert -key` and `-p12 -p12-pass` flags are mutually exclusive, you should use one or the other depending on the encoding of your certificate.
<br>
By default, the server accepts TLSv1.2 and up for clients connecting using SSL.

| Argument   | Effect                                                          |
|------------|-----------------------------------------------------------------|
| -port      | Change the port that the server will listen for connections on. |
| -cert      | The relative path to your X.509 certificate.                    |
| -key       | The relative path to your certificate key.                      |
| -p12       | The relative path to your .p12 certificate file.                |
| -p12-pass  | The relative path to the file containing the p12 cert password. |
| -i         | The relative path to your interface IP list, one per line       |
| -iface     | The interface name to use, used with -i                         |
| -a         | The relative path to an API key.<br>If specified, all clients need to include the x-api-key="KEY HERE" attribute in the stream header. |
| -whitelist | file containing JIDs / device IDs that do not require API key authentication, one per line         |
| -ban       | If specified, misbehaving clients will be IP banned from the server using iptables. If ipset is also installed, kik-go-proxy will create a new ipset hash list and ban them that way which is much more efficient. [See ip_banner.go](antispam/ip_banner.go)                 |
| -banner    | If specified, the server sends back a 'server' header to the client upon successful authentication |

## Notices
- On Unix systems, you might get errors like ```Error accepting:  accept tcp4 0.0.0.0:5222: accept4: too many open files```.<br> If you do, try [raising the ulimit.](https://stackoverflow.com/a/32325509)
- If running this on a public facing server without the -a argument, it is an open proxy. Make sure to configure your firewall to only allow trusted IPs.