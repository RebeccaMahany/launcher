package windowsupdate

import (
	"fmt"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/kolide/launcher/pkg/windows/oleconv"
)

// IUpdateSearcher searches for updates on a server.
// https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesearcher
type IUpdateSearcher struct {
	disp                                *ole.IDispatch
	CanAutomaticallyUpgradeService      bool
	ClientApplicationID                 string
	IncludePotentiallySupersededUpdates bool
	Online                              bool
	ServerSelection                     int32
	ServiceID                           string
}

func toIUpdateSearcher(updateSearcherDisp *ole.IDispatch) (*IUpdateSearcher, error) {
	var err error
	iUpdateSearcher := &IUpdateSearcher{
		disp: updateSearcherDisp,
	}

	if iUpdateSearcher.CanAutomaticallyUpgradeService, err = oleconv.ToBoolErr(oleutil.GetProperty(updateSearcherDisp, "CanAutomaticallyUpgradeService")); err != nil {
		return nil, fmt.Errorf("getting property CanAutomaticallyUpgradeService as bool: %w", err)
	}

	if iUpdateSearcher.ClientApplicationID, err = oleconv.ToStringErr(oleutil.GetProperty(updateSearcherDisp, "ClientApplicationID")); err != nil {
		return nil, fmt.Errorf("getting property ClientApplicationID as string: %w", err)
	}

	if iUpdateSearcher.IncludePotentiallySupersededUpdates, err = oleconv.ToBoolErr(oleutil.GetProperty(updateSearcherDisp, "IncludePotentiallySupersededUpdates")); err != nil {
		return nil, fmt.Errorf("getting property IncludePotentiallySupersededUpdates as bool: %w", err)
	}

	if iUpdateSearcher.Online, err = oleconv.ToBoolErr(oleutil.GetProperty(updateSearcherDisp, "Online")); err != nil {
		return nil, fmt.Errorf("getting property Online as bool: %w", err)
	}

	if iUpdateSearcher.ServerSelection, err = oleconv.ToInt32Err(oleutil.GetProperty(updateSearcherDisp, "ServerSelection")); err != nil {
		return nil, fmt.Errorf("getting property ServerSelection as int32: %w", err)
	}

	if iUpdateSearcher.ServiceID, err = oleconv.ToStringErr(oleutil.GetProperty(updateSearcherDisp, "ServiceID")); err != nil {
		return nil, fmt.Errorf("getting property ServiceID as string: %w", err)
	}

	return iUpdateSearcher, nil
}

// Search performs a synchronous search for updates. The search uses the search options that are currently configured.
// https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search
func (iUpdateSearcher *IUpdateSearcher) Search(criteria string) (*ISearchResult, error) {
	searchResultDisp, err := oleconv.ToIDispatchErr(oleutil.CallMethod(iUpdateSearcher.disp, "Search", criteria))
	if err != nil {
		return nil, fmt.Errorf("calling Search: %w", err)
	}
	return toISearchResult(searchResultDisp)
}

// QueryHistory synchronously queries the computer for the history of the update events.
// https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-queryhistory
func (iUpdateSearcher *IUpdateSearcher) QueryHistory(startIndex int32, count int32) ([]*IUpdateHistoryEntry, error) {
	updateHistoryEntriesDisp, err := oleconv.ToIDispatchErr(oleutil.CallMethod(iUpdateSearcher.disp, "QueryHistory", startIndex, count))
	if err != nil {
		return nil, fmt.Errorf("calling QueryHistory: %w", err)
	}
	return toIUpdateHistoryEntries(updateHistoryEntriesDisp)
}

// GetTotalHistoryCount returns the number of update events on the computer.
// https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-gettotalhistorycount
func (iUpdateSearcher *IUpdateSearcher) GetTotalHistoryCount() (int32, error) {
	return oleconv.ToInt32Err(oleutil.CallMethod(iUpdateSearcher.disp, "GetTotalHistoryCount"))
}

// QueryHistoryAll synchronously queries the computer for the history of all update events.
func (iUpdateSearcher *IUpdateSearcher) QueryHistoryAll() ([]*IUpdateHistoryEntry, error) {
	count, err := iUpdateSearcher.GetTotalHistoryCount()
	if err != nil {
		return nil, fmt.Errorf("getting total history count: %w", err)
	}
	return iUpdateSearcher.QueryHistory(0, count)
}
