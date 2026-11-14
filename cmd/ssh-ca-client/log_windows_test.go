package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestReport(t *testing.T) {
	origBox, origEvent := messageBox, logEvent
	t.Cleanup(func() { messageBox, logEvent = origBox, origEvent })

	type box struct {
		text    string
		boxType uint32
	}
	var boxes []box
	var events []string
	messageBox = func(text string, boxType uint32) { boxes = append(boxes, box{text, boxType}) }
	logEvent = func(msg string) { events = append(events, msg) }

	front := uint32(windows.MB_SETFOREGROUND | windows.MB_TOPMOST)

	inform("already running\n")
	if len(boxes) != 1 || boxes[0].text != "already running" || boxes[0].boxType&windows.MB_ICONINFORMATION == 0 || boxes[0].boxType&front != front {
		t.Errorf("inform() showed %+v, want one information box in front with the message", boxes)
	}
	if len(events) != 0 {
		t.Errorf("inform() logged %q, want nothing", events)
	}

	boxes = nil
	fail("could not start: no config\n")
	if len(events) != 1 || events[0] != "could not start: no config\n" {
		t.Errorf("fail() logged %q, want the message", events)
	}
	if len(boxes) != 1 || !strings.HasPrefix(boxes[0].text, "could not start: no config\n\nSee the Windows Event Log") ||
		boxes[0].boxType&windows.MB_ICONERROR == 0 || boxes[0].boxType&front != front {
		t.Errorf("fail() showed %+v, want one error box in front with the message", boxes)
	}
}
