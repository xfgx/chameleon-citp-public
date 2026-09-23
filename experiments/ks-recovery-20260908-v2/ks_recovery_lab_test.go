package chaossync

import (
 "bytes"
 "crypto/rand"
 "testing"
)
func labPlain() []byte {p:=make([]byte,128);if _,e:=rand.Read(p);e!=nil {panic(e)};return p}
func TestKSRecoveryCumulative(t *testing.T) {
 tx:=NewSender(SelftestMaster,8101,"c2n");old:=NewReceiver(SelftestMaster,8101,"c2n");old.window=24
 r:=newLabReceiver(SelftestMaster,8101,"c2n",16,8,false,false);a,b:=0,0
 for i:=1;i<=80;i++ {p:=labPlain();w:=tx.Seal(p);if i%2==1 {continue};if q,ok:=old.Ingest(w);ok {a++;if !bytes.Equal(p,q) {t.Fatal("legacy payload")}};q,ok:=r.Ingest(w);if !ok||!bytes.Equal(p,q) {t.Fatalf("frontier position %d",i)};b++;if r.stats.MaxSlots>24 {t.Fatal("slot bound")}}
 if a!=23||b!=40 {t.Fatalf("counts %d %d",a,b)}
}
func TestKSRecoveryBoundary(t *testing.T) {
 for _,gap:=range []int{15,16} {
  tx:=NewSender(SelftestMaster,8102,"c2n");r:=newLabReceiver(SelftestMaster,8102,"c2n",16,8,false,false)
  if _,ok:=r.Ingest(tx.Seal(labPlain()));!ok {t.Fatal("positive")}
  for i:=0;i<gap;i++ {tx.Seal(labPlain())}
  _,ok:=r.Ingest(tx.Seal(labPlain()));if ok!=(gap==15) {t.Fatalf("boundary gap %d",gap)}
 }
}
func TestKSRecoveryCheckpointControls(t *testing.T) {
 for _,retain:=range []bool{false,true} {
  tx:=NewSender(SelftestMaster,8103,"c2n");r:=newLabReceiver(SelftestMaster,8103,"c2n",16,8,true,retain)
  w:=tx.Seal(labPlain());bad:=append([]byte(nil),w...);bad[len(bad)-1]^=1
  before:=r.stateDigest();if _,ok:=r.Ingest(bad);ok||r.stateDigest()!=before {t.Fatal("corruption changed state")}
  if _,ok:=r.Ingest(w);!ok {t.Fatal("original rejected after corruption")};before=r.stateDigest();if _,ok:=r.Ingest(w);ok||r.stateDigest()!=before {t.Fatal("replay changed state")}
  for i:=0;i<1000;i++ {tx.Seal(labPlain())};cp:=LabCheckpoint(tx)
  if len(cp)!=100 {t.Fatal("checkpoint size")};bad=append([]byte(nil),cp...);bad[50]^=1
  before=r.stateDigest();r.Ingest(bad);if r.lastCheckpoint||r.stateDigest()!=before {t.Fatal("bad checkpoint changed state")}
  wrongs:=[]*Sender{NewSender([]byte("another unrelated laboratory master"),8103,"c2n"),NewSender(SelftestMaster,8104,"c2n"),NewSender(SelftestMaster,8103,"n2c")}
  for _,wrong:=range wrongs {for i:=0;i<32;i++ {wrong.Seal(labPlain())};r.Ingest(LabCheckpoint(wrong));if r.lastCheckpoint||r.stateDigest()!=before {t.Fatal("wrong context changed state")}}
  steps:=r.stats.Steps;r.Ingest(cp);if !r.lastCheckpoint||r.stats.Steps-steps!=16 {t.Fatal("restore work not exactly forward window")}
  before=r.stateDigest();r.Ingest(cp);if r.lastCheckpoint||r.stateDigest()!=before {t.Fatal("checkpoint replay changed state")}
  p:=labPlain();q,ok:=r.Ingest(tx.Seal(p));if !ok||!bytes.Equal(q,p) {t.Fatal("continuation failed")}
 }
}
func TestKSRecoveryRetiredSegment(t *testing.T) {
 tx:=NewSender(SelftestMaster,8105,"c2n");reset:=newLabReceiver(SelftestMaster,8105,"c2n",64,64,true,false);keep:=newLabReceiver(SelftestMaster,8105,"c2n",64,64,true,true)
 var delayed [][]byte
 for i:=1;i<=64;i++ {w:=tx.Seal(labPlain());if i>=2&&i<=33 {delayed=append(delayed,w);continue};if _,ok:=reset.Ingest(w);!ok {t.Fatal("reset positive")};if _,ok:=keep.Ingest(w);!ok {t.Fatal("keep positive")}}
 for i:=0;i<256;i++ {tx.Seal(labPlain())};cp:=LabCheckpoint(tx);reset.Ingest(cp);keep.Ingest(cp)
 p:=labPlain();w:=tx.Seal(p);for _,r:=range []*LabReceiver{reset,keep} {if q,ok:=r.Ingest(w);!ok||!bytes.Equal(p,q) {t.Fatal("new segment")}}
 for _,w:=range delayed {if _,ok:=reset.Ingest(w);ok {t.Fatal("reset unexpectedly retained old segment")};if _,ok:=keep.Ingest(w);!ok {t.Fatal("old segment lost")};if _,ok:=keep.Ingest(w);ok {t.Fatal("old segment replay")}}
 if keep.stats.MaxSlots>192 {t.Fatal("retired slot bound")}
}
func TestKSRecoverySourceRestartCharacterization(t *testing.T) {
 r:=LabSourceCharacterization(SelftestMaster,8106)
 for k,v:=range r {if !v {t.Fatalf("source characterization changed: %s",k)}}
 t.Logf("CONDITIONAL_SOURCE_BEHAVIOR %v",r)
}
