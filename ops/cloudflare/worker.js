const HOP_BY_HOP_HEADERS = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade',
];

function stripHopByHopHeaders(headers) {
  const nextHeaders = new Headers(headers);
  HOP_BY_HOP_HEADERS.forEach((header) => nextHeaders.delete(header));
  return nextHeaders;
}

export default {
  async fetch(request, env) {
    const upstreamOrigin = String(env.UPSTREAM_ORIGIN || '').trim();
    if (!upstreamOrigin) {
      return new Response('Missing UPSTREAM_ORIGIN', { status: 500 });
    }

    const incomingUrl = new URL(request.url);
    const upstreamUrl = new URL(incomingUrl.pathname + incomingUrl.search, upstreamOrigin);
    const upstreamHeaders = stripHopByHopHeaders(request.headers);
    upstreamHeaders.set('x-forwarded-host', incomingUrl.host);
    upstreamHeaders.set('x-forwarded-proto', incomingUrl.protocol.replace(':', ''));

    const upstreamRequest = new Request(upstreamUrl.toString(), {
      method: request.method,
      headers: upstreamHeaders,
      body: request.body,
      redirect: 'manual',
      cf: { cacheEverything: false },
    });

    const response = await fetch(upstreamRequest);
    const responseHeaders = stripHopByHopHeaders(response.headers);
    responseHeaders.set('x-proxy-origin', upstreamOrigin);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  },
};