package windowsupdate

import (
	"context"
	"fmt"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/kolide/launcher/pkg/traces"
	"github.com/kolide/launcher/pkg/windows/oleconv"
)

// IUpdateIdentity represents the unique identifier of an update.
// https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdateidentity
type IUpdateIdentity struct {
	disp           *ole.IDispatch
	RevisionNumber int32
	UpdateID       string
}

func toIUpdateIdentity(ctx context.Context, updateIdentityDisp *ole.IDispatch) (*IUpdateIdentity, error) {
	_, span := traces.StartSpan(ctx)
	defer span.End()

	var err error
	iUpdateIdentity := &IUpdateIdentity{
		disp: updateIdentityDisp,
	}

	if iUpdateIdentity.RevisionNumber, err = oleconv.ToInt32Err(oleutil.GetProperty(updateIdentityDisp, "RevisionNumber")); err != nil {
		return nil, fmt.Errorf("RevisionNumber: %w", err)
	}

	if iUpdateIdentity.UpdateID, err = oleconv.ToStringErr(oleutil.GetProperty(updateIdentityDisp, "UpdateID")); err != nil {
		return nil, fmt.Errorf("UpdateID: %w", err)
	}

	return iUpdateIdentity, nil
}
