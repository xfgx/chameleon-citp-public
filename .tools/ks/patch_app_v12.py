import io, os, sys, shutil, time

R = "/files/VPN"
BK = os.path.join(R, "backups", "app-v12-" + time.strftime("%Y%m%d-%H%M%S"))
os.makedirs(BK, exist_ok=True)

def rd(p):
    return io.open(p, encoding="utf-8").read()

def wr(p, s):
    io.open(p, "w", encoding="utf-8", newline="").write(s)

def backup(p):
    shutil.copy2(p, os.path.join(BK, os.path.basename(p)))

def sub(s, old, new, tag):
    c = s.count(old)
    if c != 1:
        print("PATCH_FAIL " + tag + " count=" + str(c))
        sys.exit(1)
    print("PATCH_OK " + tag)
    return s.replace(old, new, 1)

# ---------- 1. mobilecore/ks.go ----------
KS = os.path.join(R, "mobilecore", "ks.go")
s = rd(KS)
backup(KS)

s = sub(s,
  '\t"encoding/binary"\n\t"fmt"\n\t"net"\n\t"strconv"',
  '\t"encoding/binary"\n\t"errors"\n\t"fmt"\n\t"net"\n\t"os"\n\t"strconv"',
  'ks.imports')

s = sub(s,
  'var (\n\tksMu     sync.Mutex\n\tksRun    bool\n\tksCancel context.CancelFunc\n\tksTun    int\n\tksLastRx atomic.Int64\n\tmodeName atomic.Value // string: "", "citp", "ks"\n)',
  'var (\n\tksMu      sync.Mutex\n\tksRun     bool\n\tksCancel  context.CancelFunc\n\tksTun     int\n\tksTunFile *os.File     // наш дубликат tun-fd; закрываем его при остановке\n\tksSock    *net.UDPConn // рабочий UDP-сокет провода\n\tksLastRx  atomic.Int64\n\tmodeName  atomic.Value // string: "", "citp", "ks"\n)',
  'ks.vars')

s = sub(s,
  '\tksTun = int(tunFd)\n\tksCancel = cancel\n\tlocalCtx := ctx\n\tmu.Unlock()\n',
  '\tksTun = int(tunFd)\n\tksCancel = cancel\n\tlocalCtx := ctx\n\tmu.Unlock()\n\n\t// Неблокирующий режим + os.File: чтение уходит в runtime-поллер, поэтому\n\t// Close() из stopKS гарантированно будит читателя. Иначе горутина висит в\n\t// блокирующем syscall.Read на живом дескрипторе, дубликат tun-fd остаётся\n\t// открытым, и Android продолжает держать VPN-интерфейс поднятым.\n\tif err := syscall.SetNonblock(int(tunFd), true); err != nil {\n\t\tlogf("KS: SetNonblock tun: %v", err)\n\t}\n\ttunFile := os.NewFile(uintptr(tunFd), "ks-tun")\n\tif tunFile == nil {\n\t\tstopKS()\n\t\treturn "не удалось открыть tun-дескриптор"\n\t}\n\tmu.Lock()\n\tksTunFile = tunFile\n\tmu.Unlock()\n',
  'ks.tunfile')

s = sub(s,
  '\t} else {\n\t\tlogf("KS: не смог protect UDP: %v", err)\n\t}\n',
  '\t} else {\n\t\tlogf("KS: не смог protect UDP: %v", err)\n\t}\n\n\tmu.Lock()\n\tksSock = sock\n\tmu.Unlock()\n',
  'ks.sockref')

s = sub(s,
  '\t\t\tif _, err := syscall.Write(int(tunFd), plain); err != nil {',
  '\t\t\tif _, err := tunFile.Write(plain); err != nil {',
  'ks.tunwrite')

s = sub(s,
  '\t\t\tn, err := syscall.Read(int(tunFd), buf)\n\t\t\tif err != nil {\n\t\t\t\tselect {\n\t\t\t\tcase <-localCtx.Done():\n\t\t\t\t\t_ = sock.Close()\n\t\t\t\t\treturn\n\t\t\t\tdefault:\n\t\t\t\t\ttime.Sleep(20 * time.Millisecond)\n\t\t\t\t\tcontinue\n\t\t\t\t}\n\t\t\t}',
  '\t\t\tn, err := tunFile.Read(buf)\n\t\t\tif err != nil {\n\t\t\t\tselect {\n\t\t\t\tcase <-localCtx.Done():\n\t\t\t\t\t_ = sock.Close()\n\t\t\t\t\treturn\n\t\t\t\tdefault:\n\t\t\t\t}\n\t\t\t\tif errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EBADF) {\n\t\t\t\t\tlogf("KS: tun закрыт — читатель остановлен")\n\t\t\t\t\t_ = sock.Close()\n\t\t\t\t\treturn\n\t\t\t\t}\n\t\t\t\tif errors.Is(err, syscall.EAGAIN) {\n\t\t\t\t\ttime.Sleep(5 * time.Millisecond)\n\t\t\t\t\tcontinue\n\t\t\t\t}\n\t\t\t\ttime.Sleep(20 * time.Millisecond)\n\t\t\t\tcontinue\n\t\t\t}',
  'ks.tunread')

s = sub(s,
  'func stopKS() {\n\tksMu.Lock()\n\tdefer ksMu.Unlock()\n\tmu.Lock()\n\tksRun = false\n\tif modeName.Load() == "ks" {\n\t\trunning = false\n\t\tmodeName.Store("")\n\t}\n\tif ksCancel != nil {\n\t\tksCancel()\n\t\tksCancel = nil\n\t}\n\tmu.Unlock()\n}',
  'func stopKS() {\n\tksMu.Lock()\n\tdefer ksMu.Unlock()\n\tmu.Lock()\n\tksRun = false\n\tif modeName.Load() == "ks" {\n\t\trunning = false\n\t\tmodeName.Store("")\n\t}\n\tif ksCancel != nil {\n\t\tksCancel()\n\t\tksCancel = nil\n\t}\n\tf := ksTunFile\n\tksTunFile = nil\n\tsk := ksSock\n\tksSock = nil\n\tfd := ksTun\n\tksTun = 0\n\tmu.Unlock()\n\n\t// Порядок важен: сначала отмена контекста (выше), затем закрытие сокета\n\t// провода и tun-дескриптора. Пока наш дубликат tun-fd открыт, Android\n\t// считает VPN-интерфейс живым и системный туннель не опускается.\n\tif sk != nil {\n\t\t_ = sk.Close()\n\t}\n\tif f != nil {\n\t\tif err := f.Close(); err != nil {\n\t\t\tlogf("KS: закрытие tun fd=%d: %v", fd, err)\n\t\t} else {\n\t\t\tlogf("KS: tun fd=%d закрыт, интерфейс отпущен", fd)\n\t\t}\n\t} else if fd > 0 {\n\t\tif err := syscall.Close(fd); err != nil {\n\t\t\tlogf("KS: закрытие tun fd=%d: %v", fd, err)\n\t\t}\n\t}\n\tksLastRx.Store(0)\n}',
  'ks.stop')

wr(KS, s)
print("WROTE ks.go")

# ---------- 2. ChamVpnService.kt ----------
SVC = os.path.join(R, "android/app/src/main/java/com/chameleonvpn/app/ChamVpnService.kt")
s = rd(SVC)
backup(SVC)

s = sub(s,
  '        @Volatile var lastError: String = ""\n            private set\n    }',
  '        @Volatile var lastError: String = ""\n            private set\n\n        /** Реальное состояние туннеля для UI (обновляется синхронно с жизненным циклом). */\n        @Volatile var lifecycle: VpnLifecycleState = VpnLifecycleState.STOPPED\n            private set\n    }',
  'svc.lifecycle')

s = sub(s,
  '            state = VpnLifecycleState.STARTING\n            cleanupStarted.set(false)',
  '            state = VpnLifecycleState.STARTING\n            lifecycle = VpnLifecycleState.STARTING\n            cleanupStarted.set(false)',
  'svc.starting')

s = sub(s,
  '                    synchronized(stateLock) { state = VpnLifecycleState.RUNNING }',
  '                    synchronized(stateLock) { state = VpnLifecycleState.RUNNING }\n                    lifecycle = VpnLifecycleState.RUNNING',
  'svc.running')

s = sub(s,
  '        synchronized(stateLock) { state = VpnLifecycleState.FAILED }',
  '        synchronized(stateLock) { state = VpnLifecycleState.FAILED }\n        lifecycle = VpnLifecycleState.FAILED',
  'svc.failed')

s = sub(s,
  '        synchronized(stateLock) { state = VpnLifecycleState.STOPPING }',
  '        synchronized(stateLock) { state = VpnLifecycleState.STOPPING }\n        lifecycle = VpnLifecycleState.STOPPING',
  'svc.stopping')

s = sub(s,
  '        try { Mobilecore.stop() } catch (t: Throwable) { AppLog.e("VPN", "Mobilecore.stop", t) }\n        try { tun?.close() } catch (_: Throwable) {}\n        tun = null',
  '        // Порядок критичен: ядро обязано отпустить свой дубликат tun-fd, иначе\n        // Android продолжит держать VPN-интерфейс поднятым и трафик будет уходить\n        // в мёртвый туннель даже после нажатия «Отключить».\n        try { Mobilecore.stop() } catch (t: Throwable) { AppLog.e("VPN", "Mobilecore.stop", t) }\n        try { tun?.close() } catch (t: Throwable) { AppLog.e("VPN", "tun.close", t) }\n        tun = null\n        AppLog.i("VPN", "туннель отпущен, сетевой интерфейс закрыт")',
  'svc.teardown')

s = sub(s,
  '        synchronized(stateLock) { state = VpnLifecycleState.STOPPED }\n        stopSelf()',
  '        synchronized(stateLock) { state = VpnLifecycleState.STOPPED }\n        lifecycle = VpnLifecycleState.STOPPED\n        stopSelf()',
  'svc.stopped')

wr(SVC, s)
print("WROTE ChamVpnService.kt")
