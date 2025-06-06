//go:build windows
// +build windows

package watchdog

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	typesmocks "github.com/kolide/launcher/ee/agent/types/mocks"
	"github.com/kolide/launcher/pkg/threadsafebuffer"
	"github.com/stretchr/testify/require"
)

func TestInterrupt_Multiple(t *testing.T) {
	t.Parallel()
	tempRootDir := t.TempDir()
	var logBytes threadsafebuffer.ThreadSafeBuffer
	testSlogger := slog.New(slog.NewTextHandler(&logBytes, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	mockKnapsack := typesmocks.NewKnapsack(t)
	mockKnapsack.On("RootDirectory").Return(tempRootDir)
	mockKnapsack.On("Slogger").Return(testSlogger)
	mockKnapsack.On("Identifier").Return("kolide-k2").Maybe()
	mockKnapsack.On("KolideServerURL").Return("k2device.kolide.com")
	mockKnapsack.On("LauncherWatchdogEnabled").Return(false).Maybe()

	controller, _ := NewController(context.TODO(), mockKnapsack, "")

	// Let the handler run for a bit
	go controller.Run()
	time.Sleep(3 * time.Second)
	interruptStart := time.Now()
	controller.Interrupt(errors.New("test error"))

	// Confirm we can call Interrupt multiple times without blocking
	interruptComplete := make(chan struct{})
	expectedInterrupts := 3
	for i := 0; i < expectedInterrupts; i += 1 {
		go func() {
			controller.Interrupt(nil)
			interruptComplete <- struct{}{}
		}()
	}

	receivedInterrupts := 0
	for {
		if receivedInterrupts >= expectedInterrupts {
			break
		}

		select {
		case <-interruptComplete:
			receivedInterrupts += 1
			continue
		case <-time.After(5 * time.Second):
			t.Errorf("could not call interrupt multiple times and return within 5 seconds -- interrupted at %s, received %d interrupts before timeout; logs: \n%s\n", interruptStart.String(), receivedInterrupts, logBytes.String())
			t.FailNow()
		}
	}

	require.Equal(t, expectedInterrupts, receivedInterrupts)
}
