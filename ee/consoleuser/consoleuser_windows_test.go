//go:build windows
// +build windows

package consoleuser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Benchmark_explorerProcesses(b *testing.B) {
	// Report memory allocations
	b.ReportAllocs()

	for range b.N {
		procs, err := explorerProcesses(b.Context())
		assert.NoError(b, err)
		require.Greater(b, len(procs), 0)
	}
}

func Benchmark_explorerProcessesViaGetProcess(b *testing.B) {
	// Report memory allocations
	b.ReportAllocs()

	for range b.N {
		procs, err := explorerProcessesViaGetProcess(b.Context())
		assert.NoError(b, err)
		require.Greater(b, len(procs), 0)
	}
}
