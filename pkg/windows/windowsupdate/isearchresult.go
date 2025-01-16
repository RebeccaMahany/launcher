package windowsupdate

import (
	"context"
	"fmt"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/kolide/launcher/pkg/traces"
	"github.com/kolide/launcher/pkg/windows/oleconv"
)

// ISearchResult represents the result of a search.
// https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-isearchresult
type ISearchResult struct {
	disp           *ole.IDispatch
	ResultCode     int32 // enum https://docs.microsoft.com/zh-cn/windows/win32/api/wuapi/ne-wuapi-operationresultcode
	RootCategories []*ICategory
	Updates        []*IUpdate
	Warnings       []*IUpdateException
}

func toISearchResult(ctx context.Context, searchResultDisp *ole.IDispatch) (*ISearchResult, error) {
	_, span := traces.StartSpan(ctx)
	defer span.End()

	var err error
	iSearchResult := &ISearchResult{
		disp: searchResultDisp,
	}

	if iSearchResult.ResultCode, err = oleconv.ToInt32Err(oleutil.GetProperty(searchResultDisp, "ResultCode")); err != nil {
		return nil, fmt.Errorf("ResultCode: %w", err)
	}

	rootCategoriesDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(searchResultDisp, "RootCategories"))
	if err != nil {
		return nil, fmt.Errorf("RootCategories: %w", err)
	}
	if rootCategoriesDisp != nil {
		if iSearchResult.RootCategories, err = toICategories(ctx, rootCategoriesDisp); err != nil {
			return nil, fmt.Errorf("toICategories: %w", err)
		}
	}

	// Updates is a IUpdateCollection, and we want the full details. So cast it ia toIUpdates
	updatesDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(searchResultDisp, "Updates"))
	if err != nil {
		return nil, fmt.Errorf("Updates: %w", err)
	}
	if updatesDisp != nil {
		if iSearchResult.Updates, err = toIUpdates(ctx, updatesDisp); err != nil {
			return nil, fmt.Errorf("toIUpdates: %w", err)
		}
	}

	warningsDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(searchResultDisp, "Warnings"))
	if err != nil {
		return nil, fmt.Errorf("Warnings: %w", err)
	}
	if warningsDisp != nil {
		if iSearchResult.Warnings, err = toIUpdateExceptions(ctx, warningsDisp); err != nil {
			return nil, fmt.Errorf("toIUpdateExceptions: %w", err)
		}
	}

	return iSearchResult, nil
}
