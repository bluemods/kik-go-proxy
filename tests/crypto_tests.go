package main

import "fmt"

/*
Test if output is what's expected

TODO move to seperate file
*/
func testMapSorting() {
	testMap := make(map[string]string)
	testMap["a"] = "a"
	testMap["b"] = "b"
	testMap["c"] = "c"
	testMap["d"] = "d"
	testMap["e"] = "e"
	testMap["f"] = "f"
	testMap["g"] = "g"
	testMap["h"] = "h"

	sorted := makeKTag(testMap)
	fmt.Println("'" + sorted + "'")
}
