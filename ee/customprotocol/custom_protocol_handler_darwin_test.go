//go:build darwin
// +build darwin

package customprotocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_extractRequestPath(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		testCaseName  string
		requestUrl    string
		expectedPath  string
		expectedError bool
	}{
		{
			testCaseName:  "valid request",
			requestUrl:    "kolide://local/v3/cmd?box=abcd",
			expectedPath:  "/v3/cmd?box=abcd",
			expectedError: false,
		},
		{
			testCaseName:  "valid request, no query",
			requestUrl:    "kolide://local/v4/cmd",
			expectedPath:  "/v4/cmd",
			expectedError: false,
		},
		{
			testCaseName:  "invalid request",
			requestUrl:    string(rune(0x7f)), // invalid control character in URL
			expectedPath:  "",
			expectedError: true,
		},
	} {
		tt := tt
		t.Run(tt.testCaseName, func(t *testing.T) {
			t.Parallel()

			reqPath, err := extractRequestPath(tt.requestUrl)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedPath, reqPath)
			}
		})
	}
}
