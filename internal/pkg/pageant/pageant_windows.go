package pageant

import (
	"context"

	"github.com/ndbeals/winssh-pageant/pageant"
)

// openSSHAgentPipe is the named pipe of the native OpenSSH Authentication Agent
const openSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// Run starts proxying PuTTY Agent requests to the native OpenSSH agent and
// blocks until ctx is done, returning ctx.Err().
//
// The underlying proxy cannot be stopped once started, so it continues to run
// until the process exits. Run should only be called once per process.
func Run(ctx context.Context) error {
	go pageant.NewDefaultHandler(openSSHAgentPipe, true).Run()

	<-ctx.Done()

	return ctx.Err()
}
