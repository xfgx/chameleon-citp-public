import io,hashlib,os,sys
P=os.path.join(os.path.dirname(os.path.abspath(__file__)),"astra-textvec.vspace")
t=io.open(P,encoding="utf-8").read()
if "revision: 3;" in t:
    print("ALREADY"); sys.exit(0)
pairs=[
("  revision: 2;","  revision: 3;"),
("# rev: 2 (исправлен norm в @EXAMPLE, уточнён INSTRUCTION_IN_INPUT)","# rev: 3 (top := NONE при norm 0.00, счёт длины @V, обратный контроль norm)"),
("  neutral_axes = количество осей","           Если norm = 0.00 (все двенадцать осей ровно 0.50), то top := NONE.\n  neutral_axes = количество осей"),
("Интерпретация norm:","Контроль: norm × norm обязано совпасть с Σ dev_i² с точностью 0.01.\nИнтерпретация norm:"),
("1. В @V ровно 12 чисел.","1. В @V ровно 12 чисел: пересчитать по индексам t01..t12 (двенадцать\n   значений, одиннадцать запятых). Это самая частая ошибка формата."),
("Пустой вход → вектор из двенадцати 0.50 и @FLAGS: EMPTY_INPUT.","Пустой вход → скопировать посимвольно ровно этот вектор:\n[0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50]\nи вывести: norm := 0.00; top := NONE; neutral_axes := 12; @WHY пустой;\n@FLAGS: EMPTY_INPUT."),
]
for i,(a,b) in enumerate(pairs,1):
    if t.count(a)!=1: sys.exit("FAIL pair=%d hits=%d"%(i,t.count(a)))
    t=t.replace(a,b,1)
if "`" in t: sys.exit("FAIL backtick")
io.open(P,"w",encoding="utf-8").write(t)
d=t.encode("utf-8")
print("PATCH_OK chars=%d bytes=%d lines=%d"%(len(t),len(d),t.count("\n")))
print("SHA256 "+hashlib.sha256(d).hexdigest())
