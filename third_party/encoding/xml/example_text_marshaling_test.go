// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// This is a fork of Go's XML package, especially designed to work with Kik's XMPP streams.
// Taken from this commit: https://github.com/golang/go/commit/1e12eab8705d1d8d7472be9147a39caa1c8380db
// Do not use for any other purpose.
// Modifications done by Blue (https://bluesmods.com)

package xml_test

import (
	"fmt"
	"log"
	"strings"

	xml "github.com/bluemods/kik-go-proxy/third_party/encoding/xml"
)

type Size int

const (
	Unrecognized Size = iota
	Small
	Large
)

func (s *Size) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	default:
		*s = Unrecognized
	case "small":
		*s = Small
	case "large":
		*s = Large
	}
	return nil
}

func (s Size) MarshalText() ([]byte, error) {
	var name string
	switch s {
	default:
		name = "unrecognized"
	case Small:
		name = "small"
	case Large:
		name = "large"
	}
	return []byte(name), nil
}

func Example_textMarshalXML() {
	blob := `
	<sizes>
		<size>small</size>
		<size>regular</size>
		<size>large</size>
		<size>unrecognized</size>
		<size>small</size>
		<size>normal</size>
		<size>small</size>
		<size>large</size>
	</sizes>`
	var inventory struct {
		Sizes []Size `xml:"size"`
	}
	if err := xml.Unmarshal([]byte(blob), &inventory); err != nil {
		log.Fatal(err)
	}

	counts := make(map[Size]int)
	for _, size := range inventory.Sizes {
		counts[size] += 1
	}

	fmt.Printf("Inventory Counts:\n* Small:        %d\n* Large:        %d\n* Unrecognized: %d\n",
		counts[Small], counts[Large], counts[Unrecognized])

	// Output:
	// Inventory Counts:
	// * Small:        3
	// * Large:        2
	// * Unrecognized: 3
}
