package notify

import (
	"github.com/go-kit/kit/log"
)

type DesktopNotifier interface {
	Listen() error
	Interrupt(err error)
	SendNotification(title, body, actionUri string) error
}

type Notification struct {
	Title     string `json:"title"`
	Body      string `json:"body"`
	ActionUri string `json:"action_uri,omitempty"`
}

func NewDesktopNotifier(logger log.Logger, iconFilepath string) DesktopNotifier {
	return newOsSpecificNotifier(logger, iconFilepath)
}
