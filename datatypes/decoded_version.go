package datatypes

import (
	"fmt"
	"strconv"
	"strings"
)

var (
	// On this version and later, the CV token is removed
	AndroidCvCutoffVersion = RequireDecodedVersion("17.8.0.33323")

	// On this version and later, the CV token is removed.
	// Note this is currently a placeholder,
	// we will edit this to a real value once it's removed.
	IosCvCutoffVersion = RequireDecodedVersion("99.9.9.99999")
)

type DecodedVersion struct {
	major int
	minor int
	patch int
}

// IsAtOrAbove compares the version (dv) to a cutoff.
// It returns true if dv is greater than or equal to the cutoff.
func (dv DecodedVersion) IsAtOrAbove(cutoff DecodedVersion) bool {
	if dv.major > cutoff.major {
		return true
	}
	if dv.major < cutoff.major {
		return false
	}
	if dv.minor > cutoff.minor {
		return true
	}
	if dv.minor < cutoff.minor {
		return false
	}
	return dv.patch >= cutoff.patch
}

func (dv DecodedVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", dv.major, dv.minor, dv.patch)
}

// Same as ParseDecodedVersion, but panics on failure.
func RequireDecodedVersion(version string) DecodedVersion {
	dv, err := ParseDecodedVersion(version)
	if err != nil {
		panic(err)
	}
	return dv
}

func ParseDecodedVersion(version string) (DecodedVersion, error) {
	var dv DecodedVersion
	count := 3
	parts := strings.SplitN(version, ".", count+1)
	if len(parts) < count {
		return dv, fmt.Errorf("invalid version format '%s': expected at least %d parts", version, count)
	}
	var err error
	dv.major, err = strconv.Atoi(parts[0])
	if err != nil {
		return dv, err
	}
	dv.minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return dv, err
	}
	dv.patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return dv, err
	}
	return dv, nil
}
