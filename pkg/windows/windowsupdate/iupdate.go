package windowsupdate

import (
	"context"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/kolide/launcher/pkg/traces"
	"github.com/kolide/launcher/pkg/windows/oleconv"
)

// IUpdate contains the properties and methods that are available to an update.
// https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdate
type IUpdate struct {
	disp                            *ole.IDispatch
	AutoDownload                    int32 // enum https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate5-get_autodownload
	AutoSelection                   int32 // enum https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate5-get_autoselection
	AutoSelectOnWebSites            bool
	BundledUpdates                  []*IUpdateIdentity // These are full IUpdate objects, but we truncate them
	BrowseOnly                      bool               // From IUpdate3
	CanRequireSource                bool
	Categories                      []*ICategory
	CveIDs                          []string // From IUpdate2
	Deadline                        *time.Time
	DeltaCompressedContentAvailable bool
	DeltaCompressedContentPreferred bool
	DeploymentAction                int32 // enum https://docs.microsoft.com/zh-cn/windows/win32/api/wuapi/ne-wuapi-deploymentaction
	Description                     string
	DownloadContents                []*IUpdateDownloadContent
	DownloadPriority                int32 // enum https://docs.microsoft.com/zh-cn/windows/win32/api/wuapi/ne-wuapi-downloadpriority
	EulaAccepted                    bool
	EulaText                        string
	HandlerID                       string
	Identity                        *IUpdateIdentity
	Image                           *IImageInformation
	InstallationBehavior            *IInstallationBehavior
	IsBeta                          bool
	IsDownloaded                    bool
	IsHidden                        bool
	IsInstalled                     bool
	IsMandatory                     bool
	IsPresent                       bool // From IUpdate2
	IsUninstallable                 bool
	KBArticleIDs                    []string
	Languages                       []string
	LastDeploymentChangeTime        *time.Time
	MaxDownloadSize                 int64
	MinDownloadSize                 int64
	MoreInfoUrls                    []string
	MsrcSeverity                    string
	PerUser                         bool // From IUpdate4
	RebootRequired                  bool // From IUpdate2
	RecommendedCpuSpeed             int32
	RecommendedHardDiskSpace        int32
	RecommendedMemory               int32
	ReleaseNotes                    string
	SecurityBulletinIDs             []string
	SupersededUpdateIDs             []string
	SupportUrl                      string
	Title                           string
	UninstallationBehavior          *IInstallationBehavior
	UninstallationNotes             string
	UninstallationSteps             []string
}

// toIUpdates takes a IUpdateCollection and returns a []*IUpdate
func toIUpdates(ctx context.Context, updatesDisp *ole.IDispatch) ([]*IUpdate, error) {
	ctx, span := traces.StartSpan(ctx)
	defer span.End()

	count, err := oleconv.ToInt32Err(oleutil.GetProperty(updatesDisp, "Count"))
	if err != nil {
		return nil, err
	}

	updates := make([]*IUpdate, count)
	for i := 0; i < int(count); i++ {
		updateDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updatesDisp, "Item", i))
		if err != nil {
			return nil, err
		}

		update, err := toIUpdate(ctx, updateDisp)
		if err != nil {
			return nil, err
		}

		updates[i] = update
	}
	return updates, nil
}

// toIUpdates takes a IUpdateCollection and returns the a
// []*IUpdateIdentity of the contained IUpdates. This is *not* recursive, though possible is should be
func toIUpdatesIdentities(ctx context.Context, updatesDisp *ole.IDispatch) ([]*IUpdateIdentity, error) {
	ctx, span := traces.StartSpan(ctx)
	defer span.End()

	if updatesDisp == nil {
		return nil, nil
	}

	count, err := oleconv.ToInt32Err(oleutil.GetProperty(updatesDisp, "Count"))
	if err != nil {
		return nil, err
	}

	identities := make([]*IUpdateIdentity, count)
	for i := 0; i < int(count); i++ {
		updateDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updatesDisp, "Item", i))
		if err != nil {
			return nil, err
		}

		identityDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "Identity"))
		if err != nil {
			return nil, err
		}
		if identityDisp != nil {
			if identities[i], err = toIUpdateIdentity(ctx, identityDisp); err != nil {
				return nil, err
			}
		}
	}
	return identities, nil
}

func toIUpdate(ctx context.Context, updateDisp *ole.IDispatch) (*IUpdate, error) {
	ctx, span := traces.StartSpan(ctx)
	defer span.End()

	var err error
	iUpdate := &IUpdate{
		disp: updateDisp,
	}

	if iUpdate.AutoDownload, err = oleconv.ToInt32Err(oleutil.GetProperty(updateDisp, "AutoDownload")); err != nil {
		return nil, err
	}

	if iUpdate.AutoSelection, err = oleconv.ToInt32Err(oleutil.GetProperty(updateDisp, "AutoSelection")); err != nil {
		return nil, err
	}

	if iUpdate.AutoSelectOnWebSites, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "AutoSelectOnWebSites")); err != nil {
		return nil, err
	}

	if arrDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "BundledUpdates")); err != nil {
		return nil, err
	} else {
		if iUpdate.BundledUpdates, err = toIUpdatesIdentities(ctx, arrDisp); err != nil {
			return nil, err

		}
	}

	if iUpdate.BrowseOnly, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "BrowseOnly")); err != nil {
		return nil, err
	}

	if iUpdate.CanRequireSource, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "CanRequireSource")); err != nil {
		return nil, err
	}

	if categoriesDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "Categories")); err != nil {
		return nil, err
	} else if categoriesDisp != nil {
		if iUpdate.Categories, err = toICategories(ctx, categoriesDisp); err != nil {
			return nil, err
		}
	}

	if iUpdate.CveIDs, err = iStringCollectionToStringArrayErr(oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "CveIDs"))); err != nil {
		return nil, err
	}

	if iUpdate.Deadline, err = oleconv.ToTimeErr(oleutil.GetProperty(updateDisp, "Deadline")); err != nil {
		return nil, err
	}

	if iUpdate.DeltaCompressedContentAvailable, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "DeltaCompressedContentAvailable")); err != nil {
		return nil, err
	}

	if iUpdate.DeltaCompressedContentPreferred, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "DeltaCompressedContentPreferred")); err != nil {
		return nil, err
	}

	if iUpdate.DeploymentAction, err = oleconv.ToInt32Err(oleutil.GetProperty(updateDisp, "DeploymentAction")); err != nil {
		return nil, err
	}

	if iUpdate.Description, err = oleconv.ToStringErr(oleutil.GetProperty(updateDisp, "Description")); err != nil {
		return nil, err
	}

	downloadContentsDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "DownloadContents"))
	if err != nil {
		return nil, err
	}
	if downloadContentsDisp != nil {
		if iUpdate.DownloadContents, err = toIUpdateDownloadContents(ctx, downloadContentsDisp); err != nil {
			return nil, err
		}
	}

	if iUpdate.DownloadPriority, err = oleconv.ToInt32Err(oleutil.GetProperty(updateDisp, "DownloadPriority")); err != nil {
		return nil, err
	}

	if iUpdate.EulaAccepted, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "EulaAccepted")); err != nil {
		return nil, err
	}

	if iUpdate.EulaText, err = oleconv.ToStringErr(oleutil.GetProperty(updateDisp, "EulaText")); err != nil {
		return nil, err
	}

	if iUpdate.HandlerID, err = oleconv.ToStringErr(oleutil.GetProperty(updateDisp, "HandlerID")); err != nil {
		return nil, err
	}

	identityDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "Identity"))
	if err != nil {
		return nil, err
	}
	if identityDisp != nil {
		if iUpdate.Identity, err = toIUpdateIdentity(ctx, identityDisp); err != nil {
			return nil, err
		}
	}

	imageDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "Image"))
	if err != nil {
		return nil, err
	}
	if imageDisp != nil {
		if iUpdate.Image, err = toIImageInformation(ctx, imageDisp); err != nil {
			return nil, err
		}
	}

	installationBehaviorDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "InstallationBehavior"))
	if err != nil {
		return nil, err
	}
	if installationBehaviorDisp != nil {
		if iUpdate.InstallationBehavior, err = toIInstallationBehavior(ctx, installationBehaviorDisp); err != nil {
			return nil, err
		}
	}

	if iUpdate.IsBeta, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "IsBeta")); err != nil {
		return nil, err
	}

	if iUpdate.IsDownloaded, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "IsDownloaded")); err != nil {
		return nil, err
	}

	if iUpdate.IsHidden, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "IsHidden")); err != nil {
		return nil, err
	}

	if iUpdate.IsInstalled, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "IsInstalled")); err != nil {
		return nil, err
	}

	if iUpdate.IsMandatory, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "IsMandatory")); err != nil {
		return nil, err
	}

	if iUpdate.IsPresent, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "IsPresent")); err != nil {
		return nil, err
	}

	if iUpdate.IsUninstallable, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "IsUninstallable")); err != nil {
		return nil, err
	}

	if iUpdate.KBArticleIDs, err = iStringCollectionToStringArrayErr(oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "KBArticleIDs"))); err != nil {
		return nil, err
	}

	if iUpdate.Languages, err = iStringCollectionToStringArrayErr(oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "Languages"))); err != nil {
		return nil, err
	}

	if iUpdate.LastDeploymentChangeTime, err = oleconv.ToTimeErr(oleutil.GetProperty(updateDisp, "LastDeploymentChangeTime")); err != nil {
		return nil, err
	}

	if iUpdate.MaxDownloadSize, err = oleconv.ToInt64Err(oleutil.GetProperty(updateDisp, "MaxDownloadSize")); err != nil {
		return nil, err
	}

	if iUpdate.MinDownloadSize, err = oleconv.ToInt64Err(oleutil.GetProperty(updateDisp, "MinDownloadSize")); err != nil {
		return nil, err
	}

	if iUpdate.MoreInfoUrls, err = iStringCollectionToStringArrayErr(oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "MoreInfoUrls"))); err != nil {
		return nil, err
	}

	if iUpdate.MsrcSeverity, err = oleconv.ToStringErr(oleutil.GetProperty(updateDisp, "MsrcSeverity")); err != nil {
		return nil, err
	}

	if iUpdate.PerUser, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "PerUser")); err != nil {
		return nil, err
	}

	if iUpdate.RebootRequired, err = oleconv.ToBoolErr(oleutil.GetProperty(updateDisp, "RebootRequired")); err != nil {
		return nil, err
	}

	if iUpdate.RecommendedCpuSpeed, err = oleconv.ToInt32Err(oleutil.GetProperty(updateDisp, "RecommendedCpuSpeed")); err != nil {
		return nil, err
	}

	if iUpdate.RecommendedHardDiskSpace, err = oleconv.ToInt32Err(oleutil.GetProperty(updateDisp, "RecommendedHardDiskSpace")); err != nil {
		return nil, err
	}

	if iUpdate.RecommendedMemory, err = oleconv.ToInt32Err(oleutil.GetProperty(updateDisp, "RecommendedMemory")); err != nil {
		return nil, err
	}

	if iUpdate.ReleaseNotes, err = oleconv.ToStringErr(oleutil.GetProperty(updateDisp, "ReleaseNotes")); err != nil {
		return nil, err
	}

	if iUpdate.SecurityBulletinIDs, err = iStringCollectionToStringArrayErr(oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "SecurityBulletinIDs"))); err != nil {
		return nil, err
	}

	if iUpdate.SupersededUpdateIDs, err = iStringCollectionToStringArrayErr(oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "SupersededUpdateIDs"))); err != nil {
		return nil, err
	}

	if iUpdate.SupportUrl, err = oleconv.ToStringErr(oleutil.GetProperty(updateDisp, "SupportUrl")); err != nil {
		return nil, err
	}

	if iUpdate.Title, err = oleconv.ToStringErr(oleutil.GetProperty(updateDisp, "Title")); err != nil {
		return nil, err
	}

	uninstallationBehaviorDisp, err := oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "UninstallationBehavior"))
	if err != nil {
		return nil, err
	}
	if uninstallationBehaviorDisp != nil {
		if iUpdate.UninstallationBehavior, err = toIInstallationBehavior(ctx, uninstallationBehaviorDisp); err != nil {
			return nil, err
		}
	}

	if iUpdate.UninstallationNotes, err = oleconv.ToStringErr(oleutil.GetProperty(updateDisp, "UninstallationNotes")); err != nil {
		return nil, err
	}

	if iUpdate.UninstallationSteps, err = iStringCollectionToStringArrayErr(oleconv.ToIDispatchErr(oleutil.GetProperty(updateDisp, "UninstallationSteps"))); err != nil {
		return nil, err
	}

	return iUpdate, nil
}

//nolint:unused
func toIUpdateCollection(ctx context.Context, updates []*IUpdate) (*ole.IDispatch, error) {
	_, span := traces.StartSpan(ctx)
	defer span.End()

	unknown, err := oleutil.CreateObject("Microsoft.Update.UpdateColl")
	if err != nil {
		return nil, err
	}
	coll, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, err
	}
	for _, update := range updates {
		_, err := oleutil.CallMethod(coll, "Add", update.disp)
		if err != nil {
			return nil, err
		}
	}
	return coll, nil
}

// AcceptEula accepts the Microsoft Software License Terms that are associated with Windows Update. Administrators and power users can call this method.
// https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-accepteula
func (iUpdate *IUpdate) AcceptEula() error {
	_, err := oleutil.CallMethod(iUpdate.disp, "AcceptEula")
	return err
}
