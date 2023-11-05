# kik-go-proxy

Originally written in Java, but now being ported to Go (for performance reasons and learning), this tool allows you to proxy XMPP connections from your server to another by MITMing them.
<br>
The server listens on port 5222 for plain text connections by default, and 5223 by default for SSL connections.
<br>
The server connects to Kik via port 443 by default.

Use cases for this include:
- Intercepting / modifying packets
- More stable connections to Kik
- Debugging traffic from the official mobile clients (stock Kik)

## Install, build and run

```bash
git clone https://github.com/bluemods/kik-go-proxy && cd kik-go-proxy
```
```bash
go build && ./kik-go-proxy
```

## Arguments
If you use both -cert and -key, the program will use them to open an encrypted (SSL) connection.
The socket currently only accepts clients that support TLSv1.3.

| Argument | Effect                                                          |
|----------|-----------------------------------------------------------------|
| -port    | Change the port that the server will listen for connections on. |
| -cert    | The relative path to your X.509 certificate.                    |
| -key     | The relative path to your certificate key.                      |

## Notices
- On Unix systems, you might get errors like ```Error accepting:  accept tcp4 0.0.0.0:5222: accept4: too many open files```.<br> If you do, try [raising the ulimit.](https://stackoverflow.com/a/32325509)
- Since there is no current means of authentication, this is basically an open proxy server to Kik. If running this on a public facing server, make sure to configure your firewall to only allow trusted IPs.

## TODOs
- Log XMPP to file
- Multiple interface routing
- Automatically ban hosts that send invalid packets, like HTTP GET requests
