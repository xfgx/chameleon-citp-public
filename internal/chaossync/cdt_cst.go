package chaossync

// cdt_cst.go — CST (Continuity Session Ticket) для CDT: логическая
// идентичность туннеля поверх эфемерных фрагментов и мутирующих эпох.
//
// В CDT каждый фрагмент запечатан AEAD-ключом эпохи (выводится из master),
// а глобальный seq держит порядок сквозь ротации. CST добавляет поверх этого
// ЯВНОЕ доказательство непрерывности: AAD каждого фрагмента = sid эпохи
// направления, sid_m = KDF(master, "cdt-cst-v1", dir, m). Тег никогда не
// передаётся по сети — обе стороны выводят его локально, поэтому на проводе
// формат не меняется (nonce||ct), а фрагмент эпохи m доказывает знание всей
// цепочки идентичности, а не только data-ключа эпохи.
//
// Модель угроз (как у chaossync cst.go): компрометация sid одной эпохи не
// раскрывает sid других (независимый KDF на эпоху); replay фрагмента чужой
// эпохи отбрасывается (nonce-окно эпохи + AAD эпохи). Компрометация только
// data-ключа эпохи без master не даёт подделывать фрагменты (нет sid).
//
// CST включён во всех РОТАЦИОННЫХ конструкторах (NewRotatingFragmenter/
// NewRotatingDefragmenter/NewStream — боевой туннель). Burst-режим
// (фиксированная эпоха, лаборатория) остаётся без CST.

import "encoding/binary"

const cdtCstLabel = "cdt-cst-v1"

// cdtCstAAD — AAD фрагмента эпохи: sid_m направления, усечённый до 16 байт.
// Не передаётся по сети; выводится обеими сторонами локально и побитово
// одинаково (чистый KDF, как весь chaossync/CDT).
func cdtCstAAD(master []byte, epoch uint64, dir string) []byte {
	return epochSeed(master, cdtLabel(cdtCstLabel, dir), epoch)[:16]
}

// TunnelID — стабильный отпечаток идентичности туннеля для журналов обеих
// сторон: первые 8 байт цепочки от master и направления. Не зависит от
// эпохи (переживает ротации), не раскрывает ключ. Обе стороны живого
// туннеля обязаны показать одинаковый TunnelID; чужой master/направление
// дают другое значение.
func TunnelID(master []byte, dir string) uint64 {
	sid := epochSeed(master, cdtLabel(cdtCstLabel+"-tunnel", dir), 0)
	return binary.BigEndian.Uint64(sid[:8])
}
