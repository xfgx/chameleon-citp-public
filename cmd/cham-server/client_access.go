package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"chameleon/internal/chameleon"
)

type clientAccess struct {
	mu sync.Mutex
	path string
	allowed map[[32]byte]bool
	live map[net.Conn][32]byte
}

func parseAllowlist(path string)(map[[32]byte]bool,[]byte,error){
	if path==""{return nil,nil,nil}
	body,err:=os.ReadFile(path);if err!=nil{return nil,nil,err};if len(body)>1<<20{return nil,nil,fmt.Errorf("allowlist exceeds 1 MiB")}
	allowed:=make(map[[32]byte]bool)
	for i,line:=range strings.Split(string(body),"\n"){line=strings.TrimSpace(line);if line==""||strings.HasPrefix(line,"#"){continue};pub,err:=chameleon.ParseNodePubKey(line);if err!=nil{return nil,nil,fmt.Errorf("invalid public key at allowlist line %d",i+1)};var key [32]byte;copy(key[:],pub.Bytes());allowed[key]=true}
	return allowed,body,nil
}

func newClientAccess(path string)(*clientAccess,error){a:=&clientAccess{path:path,live:map[net.Conn][32]byte{}};if err:=a.reload();err!=nil{return nil,err};return a,nil}
func(a *clientAccess)snapshot()map[[32]byte]bool{a.mu.Lock();defer a.mu.Unlock();return a.allowed}
func(a *clientAccess)register(c net.Conn,pub []byte)bool{var key [32]byte;copy(key[:],pub);a.mu.Lock();defer a.mu.Unlock();if a.allowed!=nil&&!a.allowed[key]{return false};a.live[c]=key;return true}
func(a *clientAccess)unregister(c net.Conn){a.mu.Lock();delete(a.live,c);a.mu.Unlock()}
func(a *clientAccess)reload()error{
	allowed,body,err:=parseAllowlist(a.path);if err!=nil{return err}
	a.mu.Lock();a.allowed=allowed;var revoked []net.Conn
	for conn,key:=range a.live{if allowed!=nil&&!allowed[key]{revoked=append(revoked,conn);delete(a.live,conn)}};a.mu.Unlock()
	for _,conn:=range revoked{_ = conn.Close()}
	if a.path==""{return nil}
	sum:=sha256.Sum256(body);status,_:=json.Marshal(map[string]any{"sha256":hex.EncodeToString(sum[:]),"count":len(allowed),"at":time.Now().UTC()})
	f,err:=os.CreateTemp(filepath.Dir(a.path),".cham-access-*");if err!=nil{return err};name:=f.Name();defer os.Remove(name);if _,err=f.Write(status);err==nil{err=f.Sync()};closeErr:=f.Close();if err!=nil{return err};if closeErr!=nil{return closeErr};return os.Rename(name,a.path+".status.json")
}
