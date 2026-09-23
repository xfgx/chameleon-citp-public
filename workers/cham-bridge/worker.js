// cham-bridge — CDN-фронтинг ноды Chameleon (CITP) через Cloudflare Workers.
//
// Эффект: клиент соединяется WSS с <worker>.workers.dev — для провайдера,
// DPI и ТСПУ destination IP принадлежит Cloudflare (anycast, общий с
// миллионами сайтов), IP ноды в трафике клиента не появляется вообще.
// Воркер ретранслирует WebSocket-кадры на ноду (ws-listen порт), где поток
// проходит обычное аутентифицированное рукопожатие CITP — сквозное
// шифрование не нарушается, воркер видит только наш opaque-шифротекст.
//
// Маршрут: /b/<BRIDGE_TOKEN> — неверный путь получает 404 (маскировка под
// пустой сайт). Токен тот же, что на ноде (-ws-token или выведенный из ключа).

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const want = "/b/" + (env.BRIDGE_TOKEN || "");
    if (url.pathname !== want) {
      return new Response("Not found", { status: 404 });
    }
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    // Исходящий WebSocket к ноде (IP ноды виден только Cloudflare).
    const upstream = new WebSocket(env.NODE_WS_URL); // например ws://192.0.2.10:9446/b/<token>
    upstream.accept();

    server.addEventListener("message", (e) => {
      try { upstream.send(e.data); } catch (_) {}
    });
    upstream.addEventListener("message", (e) => {
      try { server.send(e.data); } catch (_) {}
    });
    const bye = () => { try { server.close(); } catch (_) {} try { upstream.close(); } catch (_) {} };
    server.addEventListener("close", bye);
    upstream.addEventListener("close", bye);
    server.addEventListener("error", bye);
    upstream.addEventListener("error", bye);

    return new Response(null, { status: 101, webSocket: client });
  },
};
