// /api/upload-photos — client photo upload for cwift.net (Cloudflare Pages Function).
// Adapted from date-of-death.com's uploader: one file per request into the shared Google Drive
// "_Client Photos" folder (a subfolder per property address), via the photo-uploads service account
// with domain-wide delegation. Same-origin only; signed form token + honeypot.
//
// Environment variables:
//   GOOGLE_SERVICE_ACCOUNT_EMAIL    (plain)   service account email
//   GOOGLE_PRIVATE_KEY              (secret)  service account private key (PEM)
//   GOOGLE_DRIVE_PHOTOS_FOLDER_ID   (plain)   parent "_Client Photos" folder id
//   RESEND_API_KEY / RESEND_FROM / RESEND_TO, FORM_SECRET

const SOURCE = "cwift.net";
const SITE_EMAIL = "contact@cwift.net";
const DEFAULT_TO = "brian@brianward.com";
const IMPERSONATE = "b@appraiser.llc";
const MAX_BYTES = 25 * 1024 * 1024;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}
function escapeHtml(str) {
  return String(str == null ? "" : str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function b64url(input) {
  const str = typeof input === "string" ? btoa(input) : btoa(String.fromCharCode(...new Uint8Array(input)));
  return str.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = { iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL, sub: IMPERSONATE, scope: "https://www.googleapis.com/auth/drive",
                  aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 };
  const signInput = b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(claim));
  const pem = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n");
  const body = pem.replace(/-----BEGIN PRIVATE KEY-----/, "").replace(/-----END PRIVATE KEY-----/, "").replace(/[\r\n\s]/g, "");
  const keyBytes = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", keyBytes.buffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signInput));
  const jwt = signInput + "." + b64url(sig);
  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });
  if (!resp.ok) throw new Error("Google auth failed: " + (await resp.text()));
  return (await resp.json()).access_token;
}

async function findOrCreateFolder(token, parentId, name) {
  const q = encodeURIComponent(`name='${name.replace(/'/g, "\\'")}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`);
  const s = await (await fetch(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name)&supportsAllDrives=true&includeItemsFromAllDrives=true`,
    { headers: { Authorization: `Bearer ${token}` } })).json();
  if (s.files && s.files.length) return s.files[0].id;
  const c = await fetch("https://www.googleapis.com/drive/v3/files?supportsAllDrives=true", {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name, mimeType: "application/vnd.google-apps.folder", parents: [parentId] }),
  });
  if (!c.ok) throw new Error("Failed to create Drive folder: " + (await c.text()));
  return (await c.json()).id;
}

async function uploadFile(token, folderId, fileName, buf, mime) {
  const boundary = "----CwiftNetUpload" + Date.now();
  const enc = new TextEncoder();
  const parts = [
    enc.encode(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`),
    enc.encode(JSON.stringify({ name: fileName, parents: [folderId] })),
    enc.encode(`\r\n--${boundary}\r\nContent-Type: ${mime}\r\n\r\n`),
    new Uint8Array(buf),
    enc.encode(`\r\n--${boundary}--`),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const body = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { body.set(p, off); off += p.length; }
  const r = await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id&supportsAllDrives=true", {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": `multipart/related; boundary=${boundary}` }, body,
  });
  if (!r.ok) throw new Error("Drive upload failed: " + (await r.text()));
  return r.json();
}

async function notify(env, email, address, count, notes, folderUrl) {
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:600px;margin:0 auto;padding:20px;color:#333;">
<h2 style="color:#0b1a30;border-bottom:3px solid #ff5a36;padding-bottom:10px;">Property photos received</h2>
<p style="font-size:15px;background:#0b1a30;color:#fff;padding:10px 14px;border-radius:4px;margin:0 0 14px;">Submitted from website: <strong>${SOURCE}</strong></p>
<table style="width:100%;border-collapse:collapse;">
<tr><td style="padding:8px 12px;font-weight:600;width:140px;">Client email</td><td style="padding:8px 12px;"><a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a></td></tr>
<tr><td style="padding:8px 12px;font-weight:600;">Property</td><td style="padding:8px 12px;">${escapeHtml(address)}</td></tr>
<tr><td style="padding:8px 12px;font-weight:600;">Files</td><td style="padding:8px 12px;">${count}</td></tr>
<tr><td style="padding:8px 12px;font-weight:600;">Drive folder</td><td style="padding:8px 12px;"><a href="${escapeHtml(folderUrl)}">Open in Google Drive</a></td></tr>
</table>
${notes ? `<h3 style="color:#555;margin-top:24px;">Notes</h3><div style="padding:12px;background:#f9f9f9;border-radius:6px;white-space:pre-wrap;">${escapeHtml(notes)}</div>` : ""}
</body></html>`;
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.RESEND_FROM || "Cwift.net <contact@brianward.com>", to: [env.RESEND_TO || DEFAULT_TO], reply_to: email,
      subject: `[${SOURCE}] Photos received (${count}) — ${address}`, html }),
  });
  if (!r.ok) console.error("Resend error:", await r.text());
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function tokenOk(token, env) {
  if (!token || typeof token !== "string") return false;
  const p = token.split(".");
  if (p.length !== 3) return false;
  if (p[2] !== await hmac(env.FORM_SECRET || env.RESEND_API_KEY || "fallback-secret", `${p[0]}.${p[1]}`)) return false;
  const age = Date.now() - Number(p[0]);
  return age >= 0 && age < 7200000;
}

export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const origin = request.headers.get("Origin") || "";
    let same = false;
    try { same = new URL(origin).host === new URL(request.url).host; } catch (e) { same = false; }
    if (!same) return json({ error: "Forbidden" }, 403);
    const fd = await request.formData();
    if (fd.get("website") || fd.get("company_url")) return json({ success: true });
    if (!(await tokenOk(fd.get("_token"), env))) return json({ error: "Please reload the page and try again." }, 400);
    const file = fd.get("file");
    const email = (fd.get("email") || "").toString().trim();
    const address = (fd.get("property_address") || "").toString().trim().replace(/[\/\\]/g, "-").slice(0, 160);
    let folderId = (fd.get("folder_id") || "").toString();
    const isLast = fd.get("is_last") === "true";
    const notes = (fd.get("notes") || "").toString().slice(0, 4000);
    const total = parseInt(fd.get("total_count") || "0", 10);
    if (!file || typeof file === "string" || !email || !address) return json({ error: "Missing file, email or property address." }, 400);
    if (file.size > MAX_BYTES) return json({ error: `${file.name} is over 25 MB.` }, 400);
    if (!/^[\w-]{10,80}$/.test(folderId)) folderId = "";
    const token = await getAccessToken(env);
    if (!folderId) folderId = await findOrCreateFolder(token, env.GOOGLE_DRIVE_PHOTOS_FOLDER_ID, address);
    const safeName = (file.name || "photo.jpg").replace(/[^\w.\- ()]/g, "_").slice(0, 120);
    await uploadFile(token, folderId, safeName, await file.arrayBuffer(), file.type || "application/octet-stream");
    const folderUrl = `https://drive.google.com/drive/folders/${folderId}`;
    if (isLast) await notify(env, email, address, total, notes, folderUrl);
    return json({ success: true, folderId });
  } catch (err) {
    console.error("Upload error:", err.message);
    return json({ error: `Upload failed. Please try again or email the photos to ${SITE_EMAIL}.` }, 500);
  }
}
