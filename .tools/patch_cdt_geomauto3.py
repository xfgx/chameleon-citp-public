import sys
nl = chr(10)
T = chr(9)

p = 'internal/chaossync/cdtstream.go'
s = open(p, encoding='utf-8').read()

old = T+'lastAck  time.Time'+nl+T+'now      func() time.Time'+nl+'}'
assert s.count(old) == 1, 'struct anchor count %d' % s.count(old)
new = (T+'lastAck  time.Time'+nl+T+'now      func() time.Time'+nl+nl+
T+'T        uint64 // период эпохи (сек), как у фрагментеров'+nl+
T+'// автопилот геометрии (EnableGeomAutopilot)'+nl+
T+'geomAuto   bool'+nl+
T+'stepper    *ClassStepper'+nl+
T+'baseOut    GeomConfig // мой TX базовый конфиг'+nl+
T+'baseIn     GeomConfig // мой RX базовый конфиг (= TX peer-а)'+nl+
T+'txClass    int        // мой текущий класс передачи'+nl+
T+'rxClass    int        // текущий класс приёма (TX peer-а)'+nl+
T+'swOut      *geomSw    // моё неподтверждённое переключение'+nl+
T+'swIn       *geomSw    // принятое от peer-а (применится на границе)'+nl+
T+'extRisk    float64    // внешний риск (DPI-профайлер, SetExtRisk)'+nl+
T+'sentTot    uint64     // сообщений отправлено в текущей эпохе'+nl+
T+'retxTot    uint64     // из них ретрансляций'+nl+
T+'curEpochS  uint64     // эпоха счётчиков'+nl+
T+'ctlHookForTest func(p []byte) bool // тестовый крюк: true = проглотить control'+nl+
'}')
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8').write(s)
print('PATCH_CDT_GEOMAUTO3_DONE (struct fields)')
