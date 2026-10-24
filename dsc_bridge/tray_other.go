//go:build !darwin

package main

import (
	"os"

	"fyne.io/systray"
)

func runTray(agentFP string, sigCh <-chan os.Signal) {
	go systray.Run(onTrayReady(agentFP), onTrayExit)
	shutdownOnSignal(sigCh)
}
