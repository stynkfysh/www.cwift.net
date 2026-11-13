// /api/form-token — issues the short-lived signed token the quote form presents.
// Same-origin only (the form lives on this site), so no CORS headers are needed.

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function onRequestGet(context) {
  const { env } = context;
  const secret = env.FORM_SECRET || env.RESEND_API_KEY || "fallback-secret";
  const ts = Date.now();
  const nonce = crypto.randomUUID();
  const sig = await hmac(secret, `${ts}.${nonce}`);
  return new Response(JSON.stringify({ token: `${ts}.${nonce}.${sig}` }), {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Robots-Tag": "noindex" },
  });
}
