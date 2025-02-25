package utils

import (
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"time"
)

const (
	_debug = false
)

func TimeMethod(name string) func() {
	start := time.Now()
	return func() {
		if _debug == true {
			log.Printf("%s took %v\n", name, time.Since(start))
		}
	}
}

// Read file with `go tool pprof your_file.pprof`
func Profile(namespace string) func() {
	if !_debug {
		return func() {}
	}
	profile, err := os.Create(fmt.Sprintf("%s-%d.prof", namespace, time.Now().UnixMilli()))
	if err != nil {
		log.Println("failed to create prof file:" + err.Error())
		return func() {}
	}
	if err := pprof.StartCPUProfile(profile); err != nil {
		log.Println("failed to start profile:" + err.Error())
		return func() {}
	}
	return pprof.StopCPUProfile
}
