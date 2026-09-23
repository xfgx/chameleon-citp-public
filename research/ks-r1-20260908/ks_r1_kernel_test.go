package chaossync
import("crypto/sha256";"encoding/binary";"encoding/json";"fmt";"os";"testing")
type r1Field struct{Mu [8]int64 `json:"mu_raw"`; E1 int64 `json:"eps1_raw"`; E2 int64 `json:"eps2_raw"`; X [8]int64 `json:"initial_raw"`; Y [8]int64 `json:"observer_initial_raw"`}
func TestKsR1KernelFixture(t *testing.T){
 root:=os.Getenv("KS_R1_DIR");buf,e:=os.ReadFile(root+"/results/fields.json");if e!=nil{t.Fatal(e)}
 var fs []r1Field;if e=json.Unmarshal(buf,&fs);e!=nil{t.Fatal(e)};out:=map[string]string{}
 for id,f:=range fs{
  p:=FieldParams{Eps1:Fxp(f.E1),Eps2:Fxp(f.E2)};var x [8]Fxp;var ys [6][8]Fxp
  for i:=0;i<8;i++{p.Mu[i]=Fxp(f.Mu[i]);p.Prev[i]=(i+7)%8;p.Next[i]=(i+1)%8;x[i]=Fxp(f.X[i]);for h:=0;h<6;h++{ys[h][i]=Fxp(f.Y[i])}}
  hsh:=sha256.New();var b [8]byte;emit:=func(z [8]Fxp){for _,v:=range z{binary.BigEndian.PutUint64(b[:],uint64(v));hsh.Write(b[:])}}
  for tick:=0;tick<2048;tick++{
   p.Step(&x);emit(x)
   for h:=0;h<6;h++{
    if h==0{p.Step(&ys[h])}else{
     k:=1;if h>=4{k=4};rot:=h==2||h==3||h==5;offset:=0;if rot{offset=tick}
     drives:=make([]int,k);values:=make([]Fxp,k);for j:=0;j<k;j++{d:=(j*(8/k)+offset)%8;drives[j]=d;values[j]=x[d]}
     c:=Fxp(int64(950)*(int64(1)<<48)/1000);if h==3{c=Fxp(int64(999)*(int64(1)<<48)/1000)}
     p.ObserverStepMulti(&ys[h],values,c,drives)
    };emit(ys[h])
   }
  };out[fmt.Sprint(id)]=fmt.Sprintf("%x",hsh.Sum(nil))
 }
 b,e:=json.MarshalIndent(out,"","  ");if e!=nil{t.Fatal(e)};if e=os.WriteFile(root+"/go_kernel_hashes.json",b,0600);e!=nil{t.Fatal(e)}
 t.Logf("Produced %d Q16.48 trajectory hashes: 2048 steps, 7 states, 8 coordinates",len(fs))
}
