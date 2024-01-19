package utils

import (
	"log"
	"time"
)

const (
	_debug = true
)

func TimeMethod(name string) func() {
	start := time.Now()
	return func() {
		if _debug == true {
			log.Printf("%s took %v\n", name, time.Since(start))
		}
	}
}
