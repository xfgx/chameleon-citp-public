//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func watchClientAccess(access *clientAccess) {
	if access.path == "" { return }
	updates:=make(chan os.Signal,1)
	signal.Notify(updates,syscall.SIGHUP)
	go func(){for range updates{if err:=access.reload();err!=nil{log.Printf("allowlist reload rejected; previous access retained: %v",err)}else{log.Printf("allowlist reloaded: %d keys; revoked sessions closed",len(access.snapshot()))}}}()
}
