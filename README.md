# kik-go-proxy

Originally written in Java, but now being ported to Go (for performance reasons and learning), this tool allows you to proxy XMPP connections from your server to another by MITMing them.

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

## Notices
- On Unix systems, you might get errors like ```Error accepting:  accept tcp4 0.0.0.0:5222: accept4: too many open files```.<br> If you do, try [raising the ulimit.](https://stackoverflow.com/a/32325509)
- Since there is no current means of authentication, this is basically an open proxy server. If running this on a public facing server, make sure to configure your firewall to only allow trusted IPs.
