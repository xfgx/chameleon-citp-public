# cham-bridge — невидимость IP нод через Cloudflare (CDN-фронтинг)

Клиент → WSS → `cham-bridge.workers.dev` (IP Cloudflare) → WS → нода → цепочка → Myserv → интернет.
Для провайдера/ТСПУ destination IP клиента — anycast Cloudflare. IP нод нигде не светятся.

## Деплой (владелец, один раз)
```bash
cd workers/cham-bridge
npx wrangler login          # аккаунт Cloudflare (тот же, где cham-bulletin)
npx wrangler deploy
```
Готовый front_url для панели/servers.json:
`wss://cham-bridge.<account>.workers.dev/b/a2501402d262723b21e8a835`

## На клиенте
1. dist/release/chamd-windows-amd64.exe (build 7cf8f8d1…) — положить в bin/.
2. В записи ноды добавить `"front_url": "<front_url выше>"` — клиент сам
   пойдёт через фронт; прямой TCP к ноде остаётся запасным (поле addr).

Лимиты free-плана Workers (100k req/день) для одного пользователя достаточны
с запасом; при росте — платный план ($5).
