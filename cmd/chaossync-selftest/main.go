// chaossync-selftest — печатает хэши канонических прогонов хаос-ядра.
//
// Гейт этапа Э1 (побитовая воспроизводимость Windows ↔ Linux):
// один и тот же бинарный код на любой платформе обязан напечатать одни и
// те же строки. Строка 1 — carrier/control-plane ядро (золотой хэш Э1,
// зафиксирован в docs/CHAOSSYNC.md). Строка 2 — keystream data-plane
// (golden-вектор KS, зафиксирован в docs/KS.md). Расхождение любой строки =
// ядро недетерминировано, дальнейшая работа бессмысленна до исправления.
package main

import (
	"fmt"
	"os"

	"chameleon/internal/chaossync"
)

func main() {
	fmt.Println(chaossync.SelftestVector())
	fmt.Println(chaossync.KsGoldenVector())
	// Строка 3 — выбор полей обоих классов + оценки lambda1 (гейт задачи
	// «хаос-пол»: бит-идентичность выбора поля Win↔Linux).
	fmt.Println(chaossync.FieldClassGoldenVector())
	os.Exit(0)
}
