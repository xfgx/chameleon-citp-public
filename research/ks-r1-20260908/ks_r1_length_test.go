package chaossync
import("bytes";"crypto/sha256";"encoding/csv";"fmt";"os";"strconv";"testing")
// Offline normal-operation contract; no sockets or production keys.
func TestKsR1LengthContract(t *testing.T){
 path:=os.Getenv("KS_R1_LENGTH_CSV");if path==""{t.Fatal("research CSV path required")}
 f,e:=os.Create(path);if e!=nil{t.Fatal(e)};defer f.Close();w:=csv.NewWriter(f)
 w.Write([]string{"seed","plaintext_bytes","wire_bytes","roundtrip"});cases:=0
 for seed:=0;seed<16;seed++{
  master:=sha256.Sum256([]byte(fmt.Sprintf("KS-R1-public-only-native-%d",seed)))
  dir:="c2n";if seed%2==1{dir="n2c"};tx:=NewSender(master[:],424242,dir);rx:=NewReceiver(master[:],424242,dir)
  for n:=0;n<=1500;n++{
   p:=bytes.Repeat([]byte{byte(seed+n)},n);wire:=tx.Seal(p)
   if len(wire)!=n+28{t.Fatalf("length mismatch seed=%d n=%d out=%d",seed,n,len(wire))}
   got,ok:=rx.Ingest(wire);if !ok||!bytes.Equal(got,p){t.Fatalf("roundtrip mismatch seed=%d n=%d",seed,n)}
   if e:=w.Write([]string{strconv.Itoa(seed),strconv.Itoa(n),strconv.Itoa(len(wire)),"1"});e!=nil{t.Fatal(e)};cases++
  }
 };w.Flush();if e:=w.Error();e!=nil{t.Fatal(e)}
 t.Logf("KS-R1 PASS: %d cases; 16 public seeds; lengths 0..1500; overhead 28; roundtrip",cases)
}
