package main

import (
	"strings"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/gui"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
)

// messageBox shows a message box with text, and the type and options in
// boxType. It is a variable so tests don't show one.
var messageBox = func(text string, boxType uint32) {
	t, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	caption, err := windows.UTF16PtrFromString(names.FriendlyAppName)
	if err != nil {
		return
	}
	_, _ = windows.MessageBox(0, t, caption, boxType)
}

// boxOptions bring a message box to the front, as one from a GUI started at
// logon could otherwise open behind other windows and never be seen
const boxOptions = windows.MB_OK | windows.MB_SETFOREGROUND | windows.MB_TOPMOST

// inform shows msg, which is only information, in a message box
var inform = func(msg string) {
	messageBox(strings.TrimSpace(msg), windows.MB_ICONINFORMATION|boxOptions)
}

// logEvent writes msg to the Event Log as an error. It is a variable so tests
// don't write events.
var logEvent = func(msg string) {
	logger, err := eventlog.Open(gui.EventLogSource)
	if err != nil {
		return
	}
	defer func() {
		_ = logger.Close()
	}()
	_ = logger.Error(1000, msg)
}

// fail writes msg, which is an error, to the Event Log and shows it in a
// message box, as the GUI has no console
var fail = func(msg string) {
	logEvent(msg)
	messageBox(strings.TrimSpace(msg)+"\n\nSee the Windows Event Log for details.", windows.MB_ICONERROR|boxOptions)
}
