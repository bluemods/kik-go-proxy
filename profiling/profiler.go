package profiling

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"sync/atomic"
)

var (
	onceToken = atomic.Bool{}
)

// Starts a web server to access the pprof profiler web interface on the specified port.
// Caller must ensure that the port is not publicly accessible (firewall rules, etc)
func OpenProfileServer(port string) {
	if !onceToken.CompareAndSwap(false, true) {
		// There should only be one server per executable instance
		log.Println("Cannot start profiling more than once")
		return
	}
	go func() {
		log.Println("pprof server listening on port " + port)
		log.Println(http.ListenAndServe(":"+port, nil))
	}()
}
