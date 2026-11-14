package pageant

import (
	"context"
	"unsafe"

	"github.com/ndbeals/winssh-pageant/pageant"
	"golang.org/x/sys/windows"
)

// openSSHAgentPipe is the named pipe of the native OpenSSH Authentication Agent
const openSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// pageantWindowClass is the class of the window that PuTTY sends agent
// requests to, which Pageant and any program standing in for it creates
const pageantWindowClass = "Pageant"

var procFindWindowW = windows.NewLazySystemDLL("user32.dll").NewProc("FindWindowW")

// pageantRunning reports whether a Pageant window already exists
var pageantRunning = func() bool {
	class, err := windows.UTF16PtrFromString(pageantWindowClass)
	if err != nil {
		return false
	}
	hwnd, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(class)), 0)

	return hwnd != 0
}

// runProxy runs the proxy, returning only if it fails to start or stops. It
// reports why with the standard log package.
var runProxy = func() {
	pageant.NewDefaultHandler(openSSHAgentPipe, true).Run()
}

// Run starts proxying PuTTY Agent requests to the native OpenSSH agent and
// blocks until ctx is done, returning ctx.Err(). It returns
// [ErrPageantRunning] without starting the proxy if another Pageant is
// already running, and [ErrStopped] if the proxy fails to start or stops.
//
// The underlying proxy cannot be stopped once started, so it continues to run
// until the process exits. Run should only be called once per process.
func Run(ctx context.Context) error {
	if pageantRunning() {
		return ErrPageantRunning
	}

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		runProxy()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stopped:
		return ErrStopped
	}
}
