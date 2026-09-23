package main

import (
 "bufio"
 "chameleon/internal/chaossync"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "os"
 "time"
)
const maxLinkBytes int64=20*1024*1024
const maxEvents=23000

type Config struct { Key string `json:"key"`; Auth string `json:"auth"`; Target string `json:"target"`; Out string `json:"out"`; Epoch uint64 `json:"epoch"` }
type Event struct {Op string `json:"op"`; Case string `json:"case,omitempty"`; Index uint64 `json:"index,omitempty"`; Stage string `json:"stage,omitempty"`; Wire []byte `json:"wire,omitempty"`}
type Response struct {Ready bool `json:"ready,omitempty"`; Done bool `json:"done,omitempty"`; Port int `json:"port,omitempty"`; Summary map[string]any `json:"summary,omitempty"`}
func must(e error) {if e!=nil {panic(e)}}
func hash(p []byte) string {h:=sha256.Sum256(p);return hex.EncodeToString(h[:])}
func logger(path string) (*json.Encoder,func()) {f,e:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);must(e);b:=bufio.NewWriterSize(f,65536);return json.NewEncoder(b),func(){must(b.Flush());must(f.Close())}}
func variantsSummary(v []*chaossync.LabVariant) map[string]chaossync.LabStats {r:=map[string]chaossync.LabStats{};for _,x:=range v {r[x.Name]=x.Stats()};return r}
func server(cfg Config,key []byte) {
 log,closeLog:=logger(cfg.Out+"/ru-raw.jsonl");defer closeLog()
 listener,e:=net.Listen("tcp4","0.0.0.0:0");must(e);defer listener.Close()
 must(listener.(*net.TCPListener).SetDeadline(time.Now().Add(45*time.Second)))
 must(json.NewEncoder(os.Stdout).Encode(Response{Ready:true,Port:listener.Addr().(*net.TCPAddr).Port}))
 c,e:=listener.Accept();must(e);defer c.Close();must(c.SetDeadline(time.Now().Add(180*time.Second)));must(listener.Close())
 reader:=io.LimitReader(c,maxLinkBytes+1);dec:=json.NewDecoder(reader);enc:=json.NewEncoder(c)
 var auth struct {Auth string `json:"auth"`};must(dec.Decode(&auth));if subtle.ConstantTimeCompare([]byte(auth.Auth),[]byte(cfg.Auth))!=1 {panic("laboratory authorization failed")}
 must(enc.Encode(Response{Ready:true}))
 var vs []*chaossync.LabVariant;current:="";events:=0;caseNo:=0;summary:=map[string]any{}
 for {
  var ev Event;must(dec.Decode(&ev));events++;if events>maxEvents {panic("event budget exceeded")}
  switch ev.Op {
  case "start":
   if vs!=nil {panic("nested scenario")};current=ev.Case;caseNo++;vs=chaossync.LabVariants(key,cfg.Epoch+uint64(caseNo),"c2n");must(enc.Encode(Response{Ready:true}))
  case "data", "checkpoint":
   if vs==nil||len(ev.Wire)>2048||len(ev.Wire)<28 {panic("invalid event")}
   mask:=0;cpMask:=0;digests:=map[string]string{};indices:=map[string]uint64{}
   for i,v:=range vs {p,ok,cp:=v.Ingest(ev.Wire);if ok {if len(p)!=128 {panic("wrong payload length")};mask|=1<<i;digests[v.Name]=hash(p);indices[v.Name]=binary.BigEndian.Uint64(p[:8])};if cp {cpMask|=1<<i}}
   must(log.Encode(map[string]any{"case":current,"index":ev.Index,"stage":ev.Stage,"op":ev.Op,"wire_sha256":hash(ev.Wire),"wire_bytes":len(ev.Wire),"ok_mask":mask,"checkpoint_mask":cpMask,"payload_sha256":digests,"decoded_index":indices}))
  case "end":
   if vs==nil {panic("missing scenario")};summary[current]=variantsSummary(vs);must(log.Encode(map[string]any{"op":"end","case":current,"stats":summary[current]}));vs=nil;must(enc.Encode(Response{Done:true}))
  case "finish":
   if vs!=nil {panic("unfinished scenario")};summary["event_count"]=events;summary["source_restart_characterization"]=chaossync.LabSourceCharacterization(key,cfg.Epoch+100)
   must(enc.Encode(Response{Done:true,Summary:summary}));b,e:=json.MarshalIndent(summary,"","  ");must(e);must(os.WriteFile(cfg.Out+"/ru-summary.json",b,0600));return
  default:panic("unknown event")
  }
 }
}
func client(cfg Config,key []byte) {
 log,closeLog:=logger(cfg.Out+"/mcp-raw.jsonl");defer closeLog()
 c,e:=net.DialTimeout("tcp4",cfg.Target,10*time.Second);must(e);defer c.Close();must(c.SetDeadline(time.Now().Add(180*time.Second)))
 bw:=bufio.NewWriterSize(c,65536);enc:=json.NewEncoder(bw);dec:=json.NewDecoder(c)
 must(enc.Encode(map[string]string{"auth":cfg.Auth}));must(bw.Flush());var response Response;must(dec.Decode(&response));if !response.Ready {panic("no positive connection control")}
 names:=[]string{"no-loss","cumulative-loss","burst-boundary","long-gap","long-gap-no-checkpoint","corruption-replay"}
 startTime:=time.Now();sentBytes:=0;sourceCount:=0
 for caseNo,name:=range names {
  must(enc.Encode(Event{Op:"start",Case:name}));must(bw.Flush());response=Response{};must(dec.Decode(&response));if !response.Ready {panic("scenario not ready")}
  tx:=chaossync.NewSender(key,cfg.Epoch+uint64(caseNo+1),"c2n");var index uint64
  type stored struct {index uint64;wire []byte;digest string}
  fresh:=func() stored {index++;p:=make([]byte,128);_,e:=rand.Read(p);must(e);binary.BigEndian.PutUint64(p[:8],index);w:=tx.Seal(p);sourceCount++;return stored{index,w,hash(p)}}
  send:=func(s stored,stage string) {must(enc.Encode(Event{Op:"data",Index:s.index,Stage:stage,Wire:s.wire}));sentBytes+=len(s.wire);if sentBytes>10*1024*1024 {panic("KS byte budget exceeded")};must(log.Encode(map[string]any{"case":name,"op":"data","stage":stage,"index":s.index,"wire_sha256":hash(s.wire),"payload_sha256":s.digest,"wire_bytes":len(s.wire)}))}
  drop:=func(s stored) {must(log.Encode(map[string]any{"case":name,"op":"drop","index":s.index,"payload_sha256":s.digest,"wire_sha256":hash(s.wire)}))}
  switch name {
  case "no-loss":for i:=0;i<256;i++ {send(fresh(),"normal")}
  case "cumulative-loss":for i:=1;i<=40000;i++ {s:=fresh();if i%2==1 {drop(s)} else {send(s,"normal")}}
  case "burst-boundary":for i:=0;i<32;i++ {send(fresh(),"warm")};for i:=0;i<8191;i++ {drop(fresh())};for i:=0;i<128;i++ {send(fresh(),"resumed")}
  case "long-gap","long-gap-no-checkpoint":
   var late []stored
   for i:=1;i<=64;i++ {s:=fresh();if i>=2&&i<=33 {late=append(late,s)} else {send(s,"warm")}}
   for i:=0;i<32768;i++ {drop(fresh())}
   cp:=chaossync.LabCheckpoint(tx)
   if name=="long-gap" {must(enc.Encode(Event{Op:"checkpoint",Index:index,Stage:"checkpoint",Wire:cp}));sentBytes+=len(cp);must(log.Encode(map[string]any{"case":name,"op":"checkpoint","index":index,"stage":"checkpoint","wire_sha256":hash(cp),"wire_bytes":len(cp)}))} else {must(log.Encode(map[string]any{"case":name,"op":"checkpoint-dropped","index":index,"wire_sha256":hash(cp),"wire_bytes":len(cp)}))}
   for i:=0;i<128;i++ {send(fresh(),"resumed")}
   for _,s:=range late {send(s,"late");send(s,"replay")}
  case "corruption-replay":s:=fresh();bad:=stored{s.index,append([]byte(nil),s.wire...),s.digest};bad.wire[len(bad.wire)-1]^=1;send(bad,"corrupt");send(s,"original");send(s,"replay")
  }
  must(enc.Encode(Event{Op:"end"}));must(bw.Flush());response=Response{};must(dec.Decode(&response));if !response.Done {panic("scenario completion failed")}
 }
 must(enc.Encode(Event{Op:"finish"}));must(bw.Flush());response=Response{};must(dec.Decode(&response));if !response.Done {panic("run completion failed")}
 summary:=map[string]any{"source_payloads":sourceCount,"ks_bytes_sent":sentBytes,"elapsed_ms":time.Since(startTime).Milliseconds(),"remote":response.Summary,"transport":"dedicated TCP carrying original KS datagrams; controlled sender omissions; not production UDP"}
 b,e:=json.MarshalIndent(summary,"","  ");must(e);must(os.WriteFile(cfg.Out+"/mcp-summary.json",b,0600));fmt.Println("LAB_CLIENT_COMPLETE")
}
func main(){
 defer func(){if recover()!=nil {fmt.Fprintln(os.Stderr,"LAB_ERROR: inspect bounded driver status; no credentials printed");os.Exit(1)}}()
 go func(){time.Sleep(180*time.Second);fmt.Fprintln(os.Stderr,"LAB_DEADLINE");os.Exit(2)}()
 var cfg Config;must(json.NewDecoder(os.Stdin).Decode(&cfg));key,e:=hex.DecodeString(cfg.Key);must(e);if len(key)!=32||len(cfg.Auth)!=64 {panic("invalid lab configuration")}
 if len(os.Args)!=2 {panic("mode required")};switch os.Args[1] {case "server":server(cfg,key);case "client":client(cfg,key);default:panic("unknown mode")}
}
