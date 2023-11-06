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
Note: If you use both -cert and -key, the program will use them to open an encrypted (SSL) connection.
<br>
The socket currently only accepts clients that support TLSv1.3.

| Argument | Effect                                                          |
|----------|-----------------------------------------------------------------|
| -port    | Change the port that the server will listen for connections on. |
| -cert    | The relative path to your X.509 certificate.                    |
| -key     | The relative path to your certificate key.                      |
| -i       | The relative path to your interface IP list, one per line       |
| -iface   | The interface name to use, default is 'eth0'                    |
| -a       | The relative path to an API key.<br>If specified, all clients need to include the x-api-key="KEY HERE" attribute in the stream header.                      |

## Notices
- On Unix systems, you might get errors like ```Error accepting:  accept tcp4 0.0.0.0:5222: accept4: too many open files```.<br> If you do, try [raising the ulimit.](https://stackoverflow.com/a/32325509)
- If running this on a public facing server without the -a argument, it is an open proxy. Make sure to configure your firewall to only allow trusted IPs.

## TODOs
- Log XMPP to file
- Automatically ban hosts that send invalid packets, like HTTP GET requests