package windowsupdate

import (
	"github.com/go-ole/go-ole"
)

// IUpdateDownloadContent represents the download content of an update.
// https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatedownloadcontent
type IUpdateDownloadContent struct {
	disp        *ole.IDispatch //nolint:unused
	DownloadUrl string
}

func toIUpdateDownloadContents(updateDownloadContentsDisp *ole.IDispatch) ([]*IUpdateDownloadContent, error) {
	// TODO
	return nil, nil
}
