package osquery

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

// default CA certs for osquery. Copied from macOS's `/etc/ssl/cert.pem`
//
//go:embed ca-bundle.crt
var defaultCaCerts []byte

// InstallCaCerts installs the default CA cert bundle into a given
// directory, and returns the path to it. We store it by hash to
// prevent repeated rewrites. We do not clean up old files, as this is
// expected to change very rarely.
func InstallCaCerts(directory string) (string, error) {
	sum := sha256.Sum256(defaultCaCerts)

	caFile := filepath.Join(directory, fmt.Sprintf("ca-certs-%x.crt", sum))

	_, err := os.Stat(caFile)

	switch {
	case os.IsNotExist(err):
		if err := os.WriteFile(caFile, defaultCaCerts, 0444); err != nil {
			return "", fmt.Errorf("writing to %s: %w", caFile, err)
		}
		return caFile, nil
	case err != nil:
		return "", fmt.Errorf("statting %s: %w", caFile, err)
	}
	return caFile, nil

}
