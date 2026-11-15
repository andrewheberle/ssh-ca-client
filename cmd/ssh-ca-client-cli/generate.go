//go:build windows || linux

package main

// The Windows version resource, with no icon or manifest. The MSI gives the
// exe the same version (templates/product.wxs), so an upgrade replaces it.
// CI sets the build version with the same flags (.github/workflows/build.yml).
//go:generate go tool go-winres simply --arch amd64,arm64 --manifest none --product-version=git-tag --file-version=git-tag
