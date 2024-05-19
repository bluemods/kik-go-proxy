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

type Animal int

const (
	Unknown Animal = iota
	Gopher
	Zebra
)

func (a *Animal) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	default:
		*a = Unknown
	case "gopher":
		*a = Gopher
	case "zebra":
		*a = Zebra
	}

	return nil
}

func (a Animal) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	var s string
	switch a {
	default:
		s = "unknown"
	case Gopher:
		s = "gopher"
	case Zebra:
		s = "zebra"
	}
	return e.EncodeElement(s, start)
}

func Example_customMarshalXML() {
	blob := `
	<animals>
		<animal>gopher</animal>
		<animal>armadillo</animal>
		<animal>zebra</animal>
		<animal>unknown</animal>
		<animal>gopher</animal>
		<animal>bee</animal>
		<animal>gopher</animal>
		<animal>zebra</animal>
	</animals>`
	var zoo struct {
		Animals []Animal `xml:"animal"`
	}
	if err := xml.Unmarshal([]byte(blob), &zoo); err != nil {
		log.Fatal(err)
	}

	census := make(map[Animal]int)
	for _, animal := range zoo.Animals {
		census[animal] += 1
	}

	fmt.Printf("Zoo Census:\n* Gophers: %d\n* Zebras:  %d\n* Unknown: %d\n",
		census[Gopher], census[Zebra], census[Unknown])

	// Output:
	// Zoo Census:
	// * Gophers: 3
	// * Zebras:  2
	// * Unknown: 3
}
