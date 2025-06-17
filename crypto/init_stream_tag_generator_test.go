package crypto

import (
	xpp "github.com/bluemods/kik-go-proxy/third_party/goxpp"
	"io"
	"strings"
	"testing"
)

func TestInitStreamTag(t *testing.T) {
	// Generated from a known-working implementation
	expected := `                 <k dev="CAN00000000000000000000000000000000" n="1" cv="727fdb643fc8c89da0c724c122cefd4711e0db18" conn="WIFI" v="17.5.1.32385" signed="e_xuNutX_M_E0w7hEtN8DijewB6kdKrgC9jbnAmXUK2b24YeYfc8-Ur9e9lyoZ_gE6IKiVR7CqpW3RTCrRT_Ww" lang="en_US" sid="b3dbc804-8acc-4bea-b08e-044b72bb8e98" anon="1" ts="1748900268494">`
	keys, err := extractKeys(expected)
	if err != nil {
		t.Fatal(err)
		return
	}
	generated := MakeKTag(keys)
	if expected != generated {
		t.Fatalf("Expected: %s, Actual: %s", expected, generated)
		return
	}
}

// Avoid circular import
func extractKeys(s string) (map[string]string, error) {
	reader := strings.NewReader(strings.Trim(s, " "))
	crReader := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	parser := xpp.NewXMLPullParser(reader, false, crReader)
	_, err := parser.Next()
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	for _, attr := range parser.Attrs {
		m[attr.Name.Local] = attr.Value
	}
	return m, nil
}
