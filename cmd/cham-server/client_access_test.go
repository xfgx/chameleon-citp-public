package main

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"chameleon/internal/chameleon"
)

func TestAllowlistMissingAndMalformedFailClosed(t *testing.T){path:=filepath.Join(t.TempDir(),"allow");if _,err:=newClientAccess(path);err==nil{t.Fatal("missing file accepted")};if err:=os.WriteFile(path,[]byte("invalid-key\n"),0600);err!=nil{t.Fatal(err)};if _,err:=newClientAccess(path);err==nil{t.Fatal("malformed file accepted")};if err:=os.WriteFile(path,nil,0600);err!=nil{t.Fatal(err)};access,err:=newClientAccess(path);if err!=nil||access.snapshot()==nil{t.Fatal("empty list must deny all",err)}}
func TestAccessReloadRevokesOnlyRemovedSessions(t *testing.T){_,pub1,_:=chameleon.GenerateNodeKey();_,pub2,_:=chameleon.GenerateNodeKey();path:=filepath.Join(t.TempDir(),"allow");_ = os.WriteFile(path,[]byte(pub1+"\n"+pub2+"\n"),0600);a,err:=newClientAccess(path);if err!=nil{t.Fatal(err)};one,peer1:=net.Pipe();defer one.Close();defer peer1.Close();two,peer2:=net.Pipe();defer two.Close();defer peer2.Close();p1,_:=base64.RawURLEncoding.DecodeString(pub1);p2,_:=base64.RawURLEncoding.DecodeString(pub2);if !a.register(one,p1)||!a.register(two,p2){t.Fatal("registration failed")};_ = os.WriteFile(path,[]byte(pub2+"\n"),0600);if err:=a.reload();err!=nil{t.Fatal(err)};_ = peer1.SetReadDeadline(time.Now().Add(time.Second));if _,err:=peer1.Read(make([]byte,1));err==nil{t.Fatal("revoked session not closed")};if a.register(one,p1){t.Fatal("handshake race admitted revoked key")};if !a.register(two,p2){t.Fatal("unrelated client was revoked")};_ = os.WriteFile(path,[]byte("broken"),0600);if a.reload()==nil{t.Fatal("malformed reload accepted")};if !a.register(two,p2){t.Fatal("previous good policy lost")}}
