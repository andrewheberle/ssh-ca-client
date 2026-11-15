//go:build windows || linux

package main

//go:generate go tool go-winres make --arch amd64,386,arm64 --product-version=git-tag --file-version=git-tag
