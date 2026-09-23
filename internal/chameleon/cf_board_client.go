package chameleon

// cf_board_client.go — клиентское чтение управляющих сообщений с bulletin-борда
// (локальный борд ноды или внешний CDN-воркер). Используется автопилотом
// клиента при обрывах: сначала опросить борд, затем переподключаться уже на
// свежие параметры.

import (
	"context"
	"fmt"
	"time"
)

// PollControlMessage опрашивает борд и расшифровывает управляющее сообщение
// для sessionID. cfSeed — общий seed Control Fabric (то же значение, что у
// ноды в -cf-seed); без него фреймы на борде — нечитаемый шифротекст, что и
// требуется по дизайну.
//
// Этап F включён по умолчанию (каноническая модель v1, эпоха 1ч): нода с
// -cf-schedule=true (дефолт) публикует сообщения с привязкой к эпохе, и
// читатель обязан её проверить. Для отката нода запускается с
// -cf-schedule=false, а клиент — со старым бинарём (см. agent.md).
func PollControlMessage(ctx context.Context, boardURL, cfSeed, sessionID string) ([]byte, error) {
	if boardURL == "" {
		return nil, fmt.Errorf("control-fabric: пустой URL борда")
	}
	cli := NewCDNCacheStateClient(boardURL)
	cf := NewControlFabric([]byte("chameleon-control-fabric:"+cfSeed), nil, nil, nil, nil).
		WithSchedule(nil, 0)
	return cf.RecoverControl(ctx, sessionID, cli)
}

// PollChannelMessages читает broadcast-канал борда (слои 6/8: θ-распределение,
// карта дорогих зон). Каждый кадр канала — самостоятельное AEAD-сообщение с
// привязкой к эпохе (PublishControlSingle): кадры дешифруются независимо,
// чужие/битые и сообщения вне окна эпох (replay старых эпох) отбрасываются.
// Возвращает валидные сообщения в порядке публикации — вызывающий берёт
// последнее. Пустой срез (без ошибки) — канал существует, но свежих
// сообщений нет.
func PollChannelMessages(ctx context.Context, boardURL, cfSeed, channelID string) ([][]byte, error) {
	_ = ctx // Poll синхронен; контекст зарезервирован под будущий клиент с ctx
	if boardURL == "" {
		return nil, fmt.Errorf("control-fabric: пустой URL борда")
	}
	cli := NewCDNCacheStateClient(boardURL)
	frames, err := cli.Poll(channelID)
	if err != nil {
		return nil, err
	}
	cf := NewControlFabric([]byte("chameleon-control-fabric:"+cfSeed), nil, nil, nil, nil).
		WithSchedule(nil, 0)
	key := cf.SessionSecret()
	now := time.Now()
	out := make([][]byte, 0, len(frames))
	for _, enc := range frames {
		dec, err := AEADDecrypt(key, enc)
		if err != nil {
			continue // чужой или битый кадр
		}
		m, err := cf.unbindMessage(dec, now)
		if err != nil {
			continue // вне окна эпох — replay старой эпохи
		}
		out = append(out, m)
	}
	return out, nil
}
