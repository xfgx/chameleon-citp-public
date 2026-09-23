package chameleon

import "time"

// Flavor — «характер» трафика по мотивам популярных российских сервисов.
// Определяет ритм CBR-паддинга: интервал, джиттер и размер кадров.
// Применяется локально на каждой стороне — синхронизация не нужна,
// поэтому клиент и сервер могут носить разные маски.
type Flavor struct {
	Base    time.Duration // базовый интервал между кадрами
	Jitter  time.Duration // случайная добавка к интервалу
	MinPad  int
	MaxPad  int
	Comment string
}

// Flavors — только российские сервисы: Instagram/YouTube заблокированы в РФ,
// имитация их паттернов сама по себе подозрительна для ТСПУ.
var Flavors = map[string]Flavor{
	"vk-video":  {25 * time.Millisecond, 15 * time.Millisecond, 900, 1400, "VK Видео: плотные чанки потока"},
	"rutube":    {30 * time.Millisecond, 20 * time.Millisecond, 800, 1400, "Рутуб: видео-сегменты"},
	"kinopoisk": {35 * time.Millisecond, 25 * time.Millisecond, 700, 1350, "Кинопоиск: стриминг"},
	"vk-feed":   {120 * time.Millisecond, 90 * time.Millisecond, 200, 900, "Лента VK: веб-активность"},
	"yandex":    {80 * time.Millisecond, 60 * time.Millisecond, 150, 800, "Яндекс: поиск/карты/дзен"},
	"sber":      {200 * time.Millisecond, 150 * time.Millisecond, 100, 500, "Сбербанк Онлайн: редкий API-трафик"},
	"gosuslugi": {250 * time.Millisecond, 200 * time.Millisecond, 100, 450, "Госуслуги: редкие обращения"},
	"wb-ozon":   {100 * time.Millisecond, 70 * time.Millisecond, 250, 1000, "Маркетплейсы: каталоги с картинками"},
	"mail":      {150 * time.Millisecond, 110 * time.Millisecond, 120, 600, "Mail.ru: почта, keep-alive"},
	// Steam: загрузка игры — долгий поток крупных чанков на высоком битрейте
	// к content-серверу. Идеальная «легенда» для CBR: ровный плотный поток
	// выглядит как скачивание игры, а не как VPN.
	"steam-dl": {15 * time.Millisecond, 8 * time.Millisecond, 1200, 1460, "Steam: загрузка игры (плотный CBR)"},
	// Steam: сам клиент в простое — редкие keep-alive и API-вызовы.
	"steam-app": {180 * time.Millisecond, 120 * time.Millisecond, 120, 700, "Steam: клиент, keep-alive/API"},
}

// FlavorByName возвращает flavor по имени или динамически синтезирует непредсказуемый профиль при "auto"/"".
// Ритм, границы кадров и джиттер генерируются из DRBG сессии — у наблюдателя никогда не будет постоянного шаблона.
func FlavorByName(name string, d *DRBG) Flavor {
	if name == "" || name == "auto" {
		if d != nil {
			// Динамический синтез параметров шейпинга:
			// Базовый интервал: 20..180 мс
			baseMs := 20 + d.Intn(160)
			// Джиттер: 10..90 мс
			jitterMs := 10 + d.Intn(80)
			// Мин/Макс паддинг с плавающими границами
			minPad := 40 + d.Intn(200)
			maxPad := minPad + 300 + d.Intn(900)

			return Flavor{
				Base:    time.Duration(baseMs) * time.Millisecond,
				Jitter:  time.Duration(jitterMs) * time.Millisecond,
				MinPad:  minPad,
				MaxPad:  maxPad,
				Comment: "Динамически синтезированный стохастический профиль",
			}
		}
		names := make([]string, 0, len(Flavors))
		for k := range Flavors {
			names = append(names, k)
		}
		return Flavors[names[0]]
	}
	if f, ok := Flavors[name]; ok {
		return f
	}
	return Flavors["yandex"]
}
