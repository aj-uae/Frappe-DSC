//go:build darwin

package main

import (
	"os"
	"runtime"

	"fyne.io/systray"
)

// Cocoa aborts the process if the status-bar item is created off the main
// thread, so on macOS the tray loop must own the main goroutine (pinned to the
// main OS thread) and the signal wait moves to a goroutine.
func init() {
	runtime.LockOSThread()
}

func runTray(agentFP string, sigCh <-chan os.Signal) {
	go shutdownOnSignal(sigCh)
	systray.Run(onTrayReady(agentFP), onTrayExit)
}
