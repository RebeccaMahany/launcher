//go:build windows
// +build windows

package consoleuser

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/kolide/launcher/ee/observability"
	"github.com/shirou/gopsutil/v4/process"
)

func CurrentUids(ctx context.Context) ([]string, error) {
	ctx, span := observability.StartSpan(ctx)
	defer span.End()

	explorerProcs, err := explorerProcesses(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting explorer processes: %w", err)
	}

	// unclear if windows will ever have more than one explorer process for a single user
	// guard against this by forcing uniqueness

	// first store uids in a map to prevent duplicates
	// most of the time it will be just 1 user, so start map at 1
	uidsMap := make(map[string]struct{}, 1)

	for _, explorerProc := range explorerProcs {
		uid, err := processOwnerUid(ctx, explorerProc)
		if err != nil {
			return nil, fmt.Errorf("getting process owner uid (for pid %d): %w", explorerProc.Pid, err)
		}
		uidsMap[uid] = struct{}{}
	}

	// convert map keys to slice
	uids := make([]string, len(uidsMap))
	uidCount := 0
	for uid := range uidsMap {
		uids[uidCount] = uid
		uidCount++
	}

	return uids, nil
}

func ExplorerProcess(ctx context.Context, uid string) (*process.Process, error) {
	ctx, span := observability.StartSpan(ctx, "uid", uid)
	defer span.End()

	explorerProcs, err := explorerProcesses(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting explorer processes: %w", err)
	}

	for _, proc := range explorerProcs {
		procOwnerUid, err := processOwnerUid(ctx, proc)
		if err != nil {
			return nil, fmt.Errorf("getting explorer process owner uid (for pid %d): %w", proc.Pid, err)
		}

		if uid == procOwnerUid {
			return proc, nil
		}
	}

	return nil, nil
}

// explorerProcesses returns a list of explorer processes whose
// filepath base is "explorer.exe".
func explorerProcesses(ctx context.Context) ([]*process.Process, error) {
	ctx, span := observability.StartSpan(ctx)
	defer span.End()

	var explorerProcs []*process.Process

	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting processes: %w", err)
	}

	for _, proc := range procs {
		exe, err := proc.ExeWithContext(ctx)
		if err != nil {
			continue
		}

		if filepath.Base(exe) == "explorer.exe" {
			explorerProcs = append(explorerProcs, proc)
		}
	}

	return explorerProcs, nil
}

func processOwnerUid(ctx context.Context, proc *process.Process) (string, error) {
	ctx, span := observability.StartSpan(ctx)
	defer span.End()

	username, err := proc.UsernameWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("getting process username (for pid %d): %w", proc.Pid, err)
	}

	// Looking up the proper UID (which on Windows, is a SID) seems to be problematic and
	// can fail for reasons we don't quite understand. We just need something to uniquely
	// identify the user, so on Windows we use the username instead of numeric UID.
	return username, nil
}
