package filewalker

import (
	"bytes"
	"regexp"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kolide/launcher/v2/ee/agent/storage"
	storageci "github.com/kolide/launcher/v2/ee/agent/storage/ci"
	"github.com/kolide/launcher/v2/ee/agent/types"
	"github.com/kolide/launcher/v2/pkg/log/multislogger"
	"github.com/stretchr/testify/require"
)

func TestUpdateConfig(t *testing.T) {
	t.Parallel()

	testRegex := regexp.MustCompile(".*")
	testSkipDir := regexp.MustCompile(`\/tmp\/\.git`)

	nonMatchingGoos := ""
	switch runtime.GOOS {
	case "darwin":
		nonMatchingGoos = "windows"
	case "windows":
		nonMatchingGoos = "linux"
	case "linux":
		nonMatchingGoos = "darwin"
	}

	for _, tt := range []struct {
		testCaseName          string
		cfg                   filewalkConfig
		expectedWalkInterval  time.Duration
		expectedRootDirs      []string
		expectedFileNameRegex *regexp.Regexp
		expectedSkipDirs      []*regexp.Regexp
	}{
		{
			testCaseName: "no overlays, no filename regex, no skip dirs",
			cfg: filewalkConfig{
				WalkInterval: duration(1 * time.Minute),
				filewalkDefinition: filewalkDefinition{
					RootDirs:      &[]string{"test-1"},
					FileNameRegex: nil,
				},
			},
			expectedWalkInterval:  1 * time.Minute,
			expectedRootDirs:      []string{"test-1"},
			expectedFileNameRegex: nil,
			expectedSkipDirs:      nil,
		},
		{
			testCaseName: "no overlays, filename regex, skip dirs",
			cfg: filewalkConfig{
				WalkInterval: duration(2 * time.Minute),
				filewalkDefinition: filewalkDefinition{
					RootDirs:      &[]string{"test-2"},
					FileNameRegex: testRegex,
					SkipDirs:      &[]*regexp.Regexp{testSkipDir},
				},
			},
			expectedWalkInterval:  2 * time.Minute,
			expectedRootDirs:      []string{"test-2"},
			expectedFileNameRegex: testRegex,
			expectedSkipDirs:      []*regexp.Regexp{testSkipDir},
		},
		{
			testCaseName: "overlay exists but doesn't apply",
			cfg: filewalkConfig{
				WalkInterval: duration(3 * time.Minute),
				filewalkDefinition: filewalkDefinition{
					RootDirs:      &[]string{"test-3"},
					FileNameRegex: nil,
				},
				Overlays: []filewalkConfigOverlay{
					{
						Filters: map[string]string{
							"goos": nonMatchingGoos,
						},
						filewalkDefinition: filewalkDefinition{
							RootDirs:      &[]string{"test-other"},
							FileNameRegex: testRegex,
							SkipDirs:      &[]*regexp.Regexp{testSkipDir},
						},
					},
				},
			},
			expectedWalkInterval:  3 * time.Minute,
			expectedRootDirs:      []string{"test-3"},
			expectedFileNameRegex: nil,
			expectedSkipDirs:      nil,
		},
		{
			testCaseName: "overlay, still no filename regex",
			cfg: filewalkConfig{
				WalkInterval: duration(4 * time.Minute),
				filewalkDefinition: filewalkDefinition{
					RootDirs:      nil,
					FileNameRegex: nil,
				},
				Overlays: []filewalkConfigOverlay{
					{
						Filters: map[string]string{
							"goos": runtime.GOOS,
						},
						filewalkDefinition: filewalkDefinition{
							RootDirs:      &[]string{"test-4"},
							FileNameRegex: nil,
						},
					},
				},
			},
			expectedWalkInterval:  4 * time.Minute,
			expectedRootDirs:      []string{"test-4"},
			expectedFileNameRegex: nil,
			expectedSkipDirs:      nil,
		},
		{
			testCaseName: "overlay, filename regex, skipdirs",
			cfg: filewalkConfig{
				WalkInterval: duration(5 * time.Minute),
				filewalkDefinition: filewalkDefinition{
					RootDirs:      nil,
					FileNameRegex: nil,
				},
				Overlays: []filewalkConfigOverlay{
					{
						Filters: map[string]string{
							"goos": runtime.GOOS,
						},
						filewalkDefinition: filewalkDefinition{
							RootDirs:      &[]string{"test-5"},
							FileNameRegex: testRegex,
							SkipDirs:      &[]*regexp.Regexp{testSkipDir},
						},
					},
				},
			},
			expectedWalkInterval:  5 * time.Minute,
			expectedRootDirs:      []string{"test-5"},
			expectedFileNameRegex: testRegex,
			expectedSkipDirs:      []*regexp.Regexp{testSkipDir},
		},
	} {
		t.Run(tt.testCaseName, func(t *testing.T) {
			t.Parallel()
		})

		slogger := multislogger.NewNopLogger()
		resultsStore, err := storageci.NewStore(t, slogger, storage.FilewalkResultsStore.String())
		require.NoError(t, err)

		testFw := newFilewalker("test_filewalk_table", tt.cfg, 0*time.Second, resultsStore, slogger)
		require.Equal(t, tt.expectedWalkInterval, testFw.walkInterval)
		require.Equal(t, tt.expectedRootDirs, testFw.rootDirs)
		require.Equal(t, tt.expectedFileNameRegex, testFw.fileNameRegex)
		require.Equal(t, tt.expectedSkipDirs, testFw.skipDirs)
		require.Nil(t, testFw.fileTypeFilter)
	}
}

// walkCountingStore counts completed filewalks by watching for last-walk-time writes.
type walkCountingStore struct {
	types.GetterSetterDeleter
	walks atomic.Int32
}

func (w *walkCountingStore) Set(k, v []byte) error {
	if bytes.HasSuffix(k, []byte("_last_walk")) {
		w.walks.Add(1)
	}
	return w.GetterSetterDeleter.Set(k, v)
}

func TestWork_walkOffset(t *testing.T) {
	t.Parallel()

	slogger := multislogger.NewNopLogger()
	baseStore, err := storageci.NewStore(t, slogger, storage.FilewalkResultsStore.String())
	require.NoError(t, err)
	store := &walkCountingStore{GetterSetterDeleter: baseStore}

	walkInterval := 200 * time.Millisecond
	walkOffset := 2 * time.Second
	testFw := newFilewalker("test_offset", filewalkConfig{
		WalkInterval:       duration(walkInterval),
		filewalkDefinition: filewalkDefinition{RootDirs: &[]string{t.TempDir()}},
	}, walkOffset, store, slogger)

	go testFw.Work()
	t.Cleanup(testFw.Stop)

	// First walk happens immediately
	time.Sleep(walkInterval / 2)
	require.Equal(t, int32(1), store.walks.Load())

	// No walks during offset delay
	time.Sleep(walkOffset - walkInterval)
	require.Equal(t, int32(1), store.walks.Load())

	// Walks resume on interval once offset has elapsed
	time.Sleep(walkOffset)
	require.Greater(t, store.walks.Load(), int32(1))
}

func BenchmarkFilewalk(b *testing.B) {
	// Pick a directory guaranteed to exist on GH runners
	var testDir string
	switch runtime.GOOS {
	case "windows":
		testDir = `D:\a\`
	case "darwin":
		testDir = "/Users/"
	default:
		testDir = "/home/"
	}

	store, err := storageci.NewStore(b, multislogger.NewNopLogger(), storage.FilewalkResultsStore.String())
	require.NoError(b, err)

	testFilewalker := newFilewalker("benchtest", filewalkConfig{
		WalkInterval: duration(1 * time.Minute),
		filewalkDefinition: filewalkDefinition{
			RootDirs:      &[]string{testDir},
			FileNameRegex: nil,
		},
	}, 0*time.Second, store, multislogger.NewNopLogger())

	b.ReportAllocs()
	for b.Loop() {
		testFilewalker.Filewalk(b.Context())
	}
}
