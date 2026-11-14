//go:build !windows

package main

import (
	"fmt"
	"os"
)

// inform prints msg, which is only information, to stdout
var inform = func(msg string) {
	_, _ = fmt.Fprint(os.Stdout, msg)
}

// fail prints msg, which is an error, to stderr
var fail = func(msg string) {
	_, _ = fmt.Fprint(os.Stderr, msg)
}
