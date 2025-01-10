package node

import (
	"bytes"
	"io"
	"strings"
	"testing"

	xpp "github.com/bluemods/kik-go-proxy/third_party/goxpp"
)

func BenchmarkBytesBufferMethod(b *testing.B) {
	for range b.N {
		newBytesBufInputStream(getSampleData()).ReadNextStanza()
	}
}

func BenchmarkStringsBuilderMethod(b *testing.B) {
	for range b.N {
		newStringsBuilderInputStream(getSampleData()).ReadNextStanza()
	}
}

func getSampleData() io.Reader {
	return strings.NewReader(`<message type="groupchat" xmlns="kik:groups" to="" id="" cts="0"><pb></pb><kik push="true" qos="true" timestamp="0" /><request xmlns="kik:message:receipt" r="true" d="true" /><content id="" app-id="com.kik.ext.gallery" v="2"><strings><app-name>Gallery</app-name><file-size>3774</file-size><allow-forward>true</allow-forward><file-content-type>image/jpeg</file-content-type><file-name></file-name></strings><extras /><hashes><sha1-original>72DF2736E1ED3B3404F80C692CB89C58F083BC71</sha1-original><sha1-scaled>065305B1C60120AB3D88636779E39A086271D4ED</sha1-scaled><blockhash-scaled>807F006F003F003F003F003F003F003F003F003F007F007F007D007F007F31CF</blockhash-scaled></hashes><images><preview>BLOB</preview><icon>iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAAXNSR0IArs4c6QAAAARzQklUCAgICHwIZIgAAAOJSURBVGiB7Zg9aFtXFMd/574PKfqILNlWwLJdDzUppFBNHdquaaDUGEoXd8jeQshW4+Lda6dmzBDaKYSaDC2F7oUO9dBADYY6OFbJh4SEKsWS7nu3iw116/ckxdfICv6N9x3dc/56555z3hWMkfKTrTe10WvGsAwUON/URNh0xd3Ymi3vSHnvt8VuqB8KXB11ZMNgYNtX7pLSRq+NW/AAAle10WvqMG3GEmNYVpz/nI+joEYdwWm5EDBqXNsbTiiHvPJQcnw9NFALezTCwKo/awIUsJye5Gb2CnnH+9+rDYFa0ONe8ynft6oYS36tCXg3kWU1P09GOZE2U47Han6ev3SXXzpNK36tnAEPYTU/Fxv8ERnlsJqfw0P62g7CqQUkEG5PlFj0UwP/ZtFPcXuiRMKCiIFSSAGzTgJX5NhayU3waWaa9y5dHtrxSrbIG26C+3+/YF93CP/1TBvDk+D4WhRy7fGvkecppxw+yxS5mb1C1rFesGJphpp7zad813xGPaZyRUblI3yVn+ejVAERO/k6DFnl8vnlGRbcJOvVXboRdSvyDCx4ST5I5kYS/BEiwvvJHAteMtImUsCU8sgOUFXOmqxymFJe5PNIAQmlUCP8949QIiRUdLG8mIX+S2gMlaDL790Wj7ptAK75Kd7208w4vvW3al3Aw3aVbxoV9nX32HrJ9fkiV2I5PWnVnzUBxhh+ellnvbp7YsHb113Wq3+SFMWHlyasVTdrZ6Aaau40KrFTpgHuNCpUQ23LrT0BFd1hTx/0tdvTB1R0x5ZbewLqYUDH9J/yO8bEjgbDYk1AWikGaXvOoa0trO1UdHymHb+v3bTjUxzAblCsCSg5PtdT+b5211N5SudRgBLhVm6GlUzxxE0VsJIpcis3Y7WZWW1kKeXwZX6OdxJpHrReUA16AEw6Hp+kp7iRKuCd907sifBxepIbqQLNw3qfVa71wI84s88sT4SCEz0G22Lsp9FIAe0wIBigMZ01gTG0YxpfpIDnQY+6xZnlVamHmueHxeAkIgU81gf82KrRM4NcbpwNPRPyQ6vGbsyMFXmIA+Drxj6Pui1WskXe8lJ4FkeAOHphyB+9Nt82n/Hzy3rs/VDsvdA48PpWoXHhQsCoeS0E1EYdxCmoKRE2Rx3FqyLCpnLF3TCwPepghsXAtivuhtqaLe/4yl0S4S7jkU41Ee76yl3ami3v/AOVHgmPLVY54gAAAABJRU5ErkJggg==</icon></images><uris /></content></message>`)
}

func newBytesBufInputStream(ioReader io.Reader) NodeInputStream {
	reader := &ByteBufferLoggingReader{
		r:   ioReader,
		buf: new(bytes.Buffer),
	}
	cr := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	return NodeInputStream{
		Reader: reader,
		Parser: *xpp.NewXMLPullParser(reader, false, cr),
	}
}

func newStringsBuilderInputStream(ioReader io.Reader) NodeInputStream {
	reader := &StringBuilderLoggingReader{
		r:   ioReader,
		buf: new(strings.Builder),
	}
	cr := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	return NodeInputStream{
		Reader: reader,
		Parser: *xpp.NewXMLPullParser(reader, false, cr),
	}
}
