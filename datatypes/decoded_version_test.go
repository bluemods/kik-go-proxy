package datatypes

import (
	"testing"
)

func TestDecodedVersions(t *testing.T) {
	testVer := RequireDecodedVersion("17.8.0.33323")

	testAtOrAbove(
		t,
		testVer,
		RequireDecodedVersion("17.0.0.00000"),
		true,
	)
	testAtOrAbove(
		t,
		testVer,
		RequireDecodedVersion("17.8.0.33323"),
		true,
	)
}

func testAtOrAbove(t *testing.T, target, subject DecodedVersion, targetShouldBeAboveSubject bool) {
	isAtOrAbove := target.IsAtOrAbove(subject)
	if targetShouldBeAboveSubject != isAtOrAbove {
		t.Fatalf("test failed: target=%s, subject=%s, targetShouldBeAboveSubject=%t", target, subject, targetShouldBeAboveSubject)
	}
}
