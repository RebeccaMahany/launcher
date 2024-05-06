//go:build darwin
// +build darwin

package customprotocol

/*
#cgo darwin CFLAGS: -DDARWIN -x objective-c
#cgo darwin LDFLAGS: -framework Foundation -framework AppKit
#include "handler.h"
*/
import "C"
import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/kolide/launcher/ee/localserver"
)

var urlInput chan string

// customProtocolHandler receives requests `kolide://` from the browser that cannot be sent
// directly to localserver; it processes and forwards them. Currently, this exists
// only to ensure Safari support for device trust. Custom protocol handling requires
// a running process for the given user, so this actor must run in launcher desktop.
type customProtocolHandler struct {
	slogger     *slog.Logger
	interrupted bool
	interrupt   chan struct{}
}

func NewCustomProtocolHandler(slogger *slog.Logger) *customProtocolHandler {
	urlInput = make(chan string, 1)

	return &customProtocolHandler{
		slogger:   slogger.With("component", "custom_protocol_handler"),
		interrupt: make(chan struct{}),
	}
}

func (c *customProtocolHandler) Execute() error {
	C.StartURLHandler()

	for {
		select {
		case i := <-urlInput:
			if err := c.handleCustomProtocolRequest(i); err != nil {
				c.slogger.Log(context.TODO(), slog.LevelWarn,
					"could not handle custom protocol request",
					"err", err,
				)
			}
		case <-c.interrupt:
			c.slogger.Log(context.TODO(), slog.LevelDebug,
				"received external interrupt, stopping",
			)
			return nil
		}
	}
}

func (c *customProtocolHandler) Interrupt(_ error) {
	c.slogger.Log(context.TODO(), slog.LevelInfo,
		"received interrupt",
	)

	// Only perform shutdown tasks on first call to interrupt -- no need to repeat on potential extra calls.
	if c.interrupted {
		return
	}
	c.interrupted = true

	c.interrupt <- struct{}{}
}

// handleCustomProtocolRequest receives requests, performs a small amount of validation,
// and then forwards them to launcher root's localserver.
func (c *customProtocolHandler) handleCustomProtocolRequest(requestUrl string) error {
	c.slogger.Log(context.TODO(), slog.LevelInfo,
		"received custom protocol request",
		"request_url", requestUrl,
	)

	requestPath, err := extractRequestPath(requestUrl)
	if err != nil {
		return fmt.Errorf("extracting request path from URL: %w", err)
	}

	// Collect errors to return IFF we are unable to successfully forward to any port
	var forwardingResultsLock sync.Mutex
	forwardingErrorMsgs := make([]string, 0)
	successfullyForwarded := false

	// Attempt to forward the request to every port launcher potentially listens on
	var wg sync.WaitGroup
	for _, p := range localserver.PortList {
		wg.Add(1)
		p := p
		go func() {
			defer wg.Done()

			err := forwardRequest(p, requestPath)

			forwardingResultsLock.Lock()
			defer forwardingResultsLock.Unlock()
			if err != nil {
				forwardingErrorMsgs = append(forwardingErrorMsgs, err.Error())
			} else {
				successfullyForwarded = true
			}
		}()
	}

	wg.Wait()

	if !successfullyForwarded {
		return fmt.Errorf("unable to successfully forward request to any launcher port: %s", strings.Join(forwardingErrorMsgs, ";"))
	}

	return nil
}

// extractRequestPath pulls out the path and query from the custom protocol request, discarding the
// scheme/host.
func extractRequestPath(requestUrl string) (string, error) {
	// Validate that we received a legitimate-looking URL
	parsedUrl, err := url.Parse(requestUrl)
	if err != nil {
		return "", fmt.Errorf("unparseable url: %w", err)
	}

	return parsedUrl.RequestURI(), nil
}

// forwardRequest makes the request with the given `reqPath` to localserver at the given `port`.
func forwardRequest(port int, reqPath string) error {
	reqUrl := fmt.Sprintf("http://localhost:%d/%s", port, strings.TrimPrefix(reqPath, "/"))
	req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
	if err != nil {
		return fmt.Errorf("creating forward request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("received non-200 status code %d from localhost and could not read response body: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("received non-200 status code %d from localhost: %s", resp.StatusCode, string(respBytes))
	}

	return nil
}

//export handleURL
func handleURL(u *C.char) {
	urlInput <- C.GoString(u)
}
