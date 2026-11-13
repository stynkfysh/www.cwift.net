// /api/order — order/request handler for cwift.net (Cloudflare Pages Function).
// Adapted from the market-area-site contact.js template (325appraisal.com build): honeypot, signed form
// token, dwell time, Cloudflare Turnstile and content scoring; same-origin, no phone number anywhere.
//
// Environment variables (Pages project > Settings > Variables and Secrets):
//   RESEND_API_KEY        (secret)  Resend API key
//   RESEND_FROM                     verified sender, e.g. "Cwift.net <contact@brianward.com>"
//   RESEND_TO                       lead destination (brian@brianward.com)
//   FORM_SECRET           (secret)  HMAC key for the form token
//   TURNSTILE_SECRET_KEY  (secret)  secret for this site's own Turnstile widget

const SOURCE = "cwift.net";
const BRAND = "Cwift.net";
const SITE_URL = "https://www.cwift.net";
const SITE_EMAIL = "contact@cwift.net";
const DEFAULT_FROM = `${BRAND} <contact@brianward.com>`;
const DEFAULT_TO = "brian@brianward.com";
const REPLY_TO_CLIENT = "brian@brianward.com";

const SERVICES = {
  "rush-standard": "24-Hour Standard Desktop — $675",
  "rush-basic": "24-Hour Basic Desktop — $450",
  "std-standard": "Standard Desktop, 5–10 business days — $449",
  "std-basic": "Basic Desktop, 5–10 business days — $299",
  "not-sure": "Not sure — recommend one",
};
const PURPOSES = {
  "date-of-death": "Date of death / step-up in basis",
  "trust-estate": "Trust or estate administration",
  "divorce": "Divorce or legal separation",
  "family-transfers": "Family sale, transfer or co-owner buyout",
  "gift-tax": "Gift tax (Form 709)",
  "prop-19": "Prop 19 parent-child transfer",
  "property-tax-appeal": "Property tax appeal",
  "bankruptcy": "Bankruptcy",
  "pre-listing": "Before selling (pre-listing)",
  "pre-purchase": "Before buying (pre-purchase)",
  "immigration": "Immigration (Form I-864)",
  "bail-bonds": "Bail or property bond",
  "other": "Other",
};

const CLEAN = "clean", SUSPECT = "suspect", SPAM = "spam";
const DROP_AT = 90, FLAG_AT = 50;
const BAD_EMAIL_DOMAINS = ["bk.ru", "mail.ru", "list.ru", "inbox.ru", "rambler.ru", "yandex.ru", "internet.ru", "bigpind.com", "outllook.com"];
const JUNK_PLACES = ["leo", "tro", "mtskheta", "lilongwe", "porsgrunn", "shekhupura", "lac la biche", "tbilisi", "kralupy", "gujranwala"];

function scoreSubmission(f) {
  const reasons = [];
  let score = 0;
  const add = (n, why) => { score += n; reasons.push(`${why} (+${n})`); };
  const name = (f.name || "").trim(), email = (f.email || "").trim();
  const street = (f.street || "").trim(), city = (f.city || "").trim(), zip = (f.zip || "").trim();
  const message = (f.message || "").trim();
  const all = [name, email, street, city, zip, message].join(" ");
  if (f.honeypot) add(100, "hidden honeypot field was filled");
  if (f.turnstile === "failed") add(60, "failed Cloudflare Turnstile");
  if (f.turnstile === "passed") { score -= 40; reasons.push("passed Cloudflare Turnstile (-40)"); }
  if (!f.tokenValid && f.turnstile !== "passed" && f.turnstile !== "failed") add(40, "no valid form token (posted directly to the API)");
  if (f.dwellMs != null && f.dwellMs < 3000) add(40, "submitted under 3s after page load");
  if (/[Ѐ-ӿ؀-ۿ一-鿿]/.test(all)) add(50, "non-Latin script");
  const domain = (email.split("@")[1] || "").toLowerCase();
  if (BAD_EMAIL_DOMAINS.includes(domain)) add(40, `email domain ${domain}`);
  if (name && !/\s/.test(name) && name.length >= 8) add(25, "single-token name");
  if (street && city && street.toLowerCase() === city.toLowerCase()) add(30, "street and city are identical");
  if (street && !/\d/.test(street) && !/^apn/i.test(street)) add(25, "street address contains no number");
  if (JUNK_PLACES.includes(city.toLowerCase()) || JUNK_PLACES.includes(street.toLowerCase())) add(30, "known placeholder locality");
  if (zip && !/^\d{5}(-\d{4})?$/.test(zip)) add(20, "zip is not a US 5-digit code");
  if (/https?:\/\/|www\.|\[url|\[link|<a\s/i.test(message)) add(35, "message contains a link");
  if (f.purpose && !PURPOSES[f.purpose]) add(20, "purpose is not one of the form options");
  if (score < 0) score = 0;
  return { score, verdict: score >= DROP_AT ? SPAM : score >= FLAG_AT ? SUSPECT : CLEAN, reasons };
}

async function verifyTurnstile(token, ip, env) {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) return "unconfigured";
  if (!token) return "failed";
  try {
    const body = new FormData();
    body.append("secret", secret);
    body.append("response", token);
    if (ip) body.append("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    const d = await r.json();
    return d.success ? "passed" : "failed";
  } catch (e) {
    console.error("Turnstile verify error:", e.message);
    return "unconfigured";
  }
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function verifyToken(token, env) {
  if (!token || typeof token !== "string") return { valid: false, dwellMs: null };
  const parts = token.split(".");
  if (parts.length !== 3) return { valid: false, dwellMs: null };
  const [ts, nonce, sig] = parts;
  const expected = await hmac(env.FORM_SECRET || env.RESEND_API_KEY || "fallback-secret", `${ts}.${nonce}`);
  if (sig !== expected) return { valid: false, dwellMs: null };
  const age = Date.now() - Number(ts);
  if (!(age >= 0 && age < 7200000)) return { valid: false, dwellMs: age };
  return { valid: true, dwellMs: age };
}

function wantsJson(request) {
  return (request.headers.get("Accept") || "").includes("application/json");
}
function reply(request, ok, error) {
  if (wantsJson(request)) {
    return new Response(JSON.stringify(ok ? { ok: true } : { ok: false, error }), {
      status: ok ? 200 : 400, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }
  return Response.redirect(new URL(`/order?status=${ok ? "success" : "error"}#order`, request.url).toString(), 303);
}

async function sendMail(env, payload) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const origin = request.headers.get("Origin");
  if (origin) {
    try { if (new URL(origin).host !== new URL(request.url).host) return reply(request, false, "Please submit the form from the website."); }
    catch (e) { return reply(request, false, "Please submit the form from the website."); }
  }
  let fd;
  try { fd = await request.formData(); } catch (e) { return reply(request, false, "Please fill in the form and try again."); }
  const get = (k) => (fd.get(k) || "").toString().trim();

  const name = get("name"), email = get("email"), role = get("role");
  const street = get("street"), city = get("city"), zip = get("zip");
  const propertyType = get("property_type"), purpose = get("purpose"), purposeOther = get("purpose_other");
  const valuation = get("valuation"), effDate = get("effective_date"), service = get("service");
  const deadline = get("deadline"), message = get("notes");
  const honeypot = get("website") || get("company_url");
  const dwellClient = Number(get("dwell_ms")) || null;

  if (!name || !email || !street || !city || !purpose || !service) return reply(request, false, "Please complete the required fields.");
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return reply(request, false, "Please check your email address.");
  if (valuation === "past" && !effDate) return reply(request, false, "Please enter the date the value is needed for.");

  const turnstile = await verifyTurnstile(fd.get("cf-turnstile-response"), request.headers.get("CF-Connecting-IP"), env);
  const tok = await verifyToken(get("form_token"), env);
  const dwellMs = tok.valid ? tok.dwellMs : dwellClient;
  const { score, verdict, reasons } = scoreSubmission({ name, email, street, city, zip, message, purpose, honeypot, tokenValid: tok.valid, dwellMs, turnstile });

  if (verdict === SPAM) {
    console.log(JSON.stringify({ blocked: true, source: SOURCE, name, email, score, reasons }));
    return reply(request, true);
  }
  const flagged = verdict === SUSPECT;
  const fullAddress = [street, city, zip].filter(Boolean).join(", ");
  const purposeLabel = (PURPOSES[purpose] || purpose) + (purpose === "other" && purposeOther ? `: ${purposeOther}` : "");
  const serviceLabel = SERVICES[service] || service;
  const dateLabel = valuation === "past" ? formatDate(effDate) : "Current (today)";
  const rush = service.startsWith("rush");

  const rows = [
    ["Source Website", SOURCE],
    ["Service", serviceLabel],
    ["Name", name],
    ["Email", email],
    ["Role", role || "Not given"],
    ["Property Address", fullAddress],
    ["Property Type", propertyType || "Not given"],
    ["Purpose", purposeLabel],
    ["Effective Date", dateLabel],
    ["Deadline", deadline || "None given"],
    ["Notes", message || "None"],
  ];
  const text = [
    `New ${rush ? "24-HOUR " : ""}Appraisal Request${flagged ? " [POSSIBLE SPAM]" : ""}`, "",
    `SUBMITTED FROM WEBSITE: ${SOURCE}`,
    flagged ? `\nFLAGGED AS POSSIBLE SPAM (score ${score}): ${reasons.join("; ")}\n` : "",
    ...rows.map(([k, v]) => `${k}: ${v}`),
  ].join("\n").trim();
  const flagBanner = flagged
    ? `<p style="font-size:14px;background:#fbe9e7;border:1px solid #d32f2f;color:#c62828;padding:10px 14px;border-radius:4px;font-family:Arial,sans-serif;margin:0 0 14px;"><strong>Possible spam (score ${score}).</strong> Delivered so you can judge it yourself. No confirmation email was sent.<br><span style="font-size:12px;">${escapeHtml(reasons.join("; "))}</span></p>`
    : "";
  const html = `<h2 style="font-family:Arial,sans-serif;">New ${rush ? "24-hour " : ""}appraisal request</h2>
${flagBanner}
<p style="font-size:15px;background:${rush ? "#ff5a36" : "#0b1a30"};color:#fff;padding:10px 14px;border-radius:4px;font-family:Arial,sans-serif;margin:0 0 14px;">Submitted from website: <strong>${SOURCE}</strong> &middot; ${escapeHtml(serviceLabel)}</p>
<table style="border-collapse:collapse;font-family:Arial,sans-serif;">
${rows.map(([k, v], i) => `<tr${i % 2 ? "" : ' style="background:#f5f5f5;"'}><td style="padding:6px 12px;font-weight:bold;vertical-align:top;">${escapeHtml(k)}</td><td style="padding:6px 12px;">${k === "Email" ? `<a href="mailto:${escapeHtml(v)}">${escapeHtml(v)}</a>` : escapeHtml(v)}</td></tr>`).join("\n")}
</table>`;

  const from = env.RESEND_FROM || DEFAULT_FROM;
  try {
    await sendMail(env, {
      from, to: [env.RESEND_TO || DEFAULT_TO], reply_to: email,
      subject: `${flagged ? "[POSSIBLE SPAM] " : ""}[${SOURCE}] ${rush ? "24-HOUR " : ""}Appraisal Request – ${purposeLabel} – ${fullAddress} – ${name}`,
      text, html,
    });
  } catch (err) {
    console.error("Resend error:", err.message);
    return reply(request, false, `We couldn't send your request just now. Please email ${SITE_EMAIL}.`);
  }

  if (verdict === CLEAN) {
    const uploadUrl = `${SITE_URL}/upload?email=${encodeURIComponent(email)}&address=${encodeURIComponent(fullAddress)}`;
    const d = { name, email, fullAddress, purposeLabel, serviceLabel, dateLabel, deadline, message, uploadUrl, rush };
    try {
      await sendMail(env, {
        from, to: [email], reply_to: REPLY_TO_CLIENT,
        subject: `We received your appraisal request — ${BRAND}`,
        text: autoReplyText(d), html: autoReplyHtml(d),
      });
    } catch (err) {
      console.error("Auto-reply failed (request still received):", err.message);
    }
  }
  return reply(request, true);
}

function autoReplyText(d) {
  return `Hi ${d.name},

Thank you for your appraisal request. Here is what happens next:

1. Brian Ward reviews your request and emails a secure invoice, along with any questions.
2. Pay the invoice and send your photos.${d.rush ? "\n3. The 24-hour clock starts when both payment and photos are in. It runs seven days a week, weekends and holidays included." : "\n3. Your appraisal is delivered within 5–10 business days after payment and photos."}

Send photos now to save time:
${d.uploadUrl}
(or simply reply to this email with them attached)

WHAT YOU SENT
Service: ${d.serviceLabel}
Property: ${d.fullAddress}
Purpose: ${d.purposeLabel}
Effective date: ${d.dateLabel}
Deadline: ${d.deadline || "None given"}
Notes: ${d.message || "None"}

Thank you,
Brian Ward
${BRAND} — 24-hour desktop appraisals
California Certified Residential Real Estate Appraiser, License AR036053
${SITE_URL}

This is an automatic confirmation. You do not need to submit the form again.`;
}

function autoReplyHtml(d) {
  const row = (l, v) => v ? `<tr><td style="padding:6px 12px;font-weight:600;width:150px;vertical-align:top;">${escapeHtml(l)}</td><td style="padding:6px 12px;">${escapeHtml(v)}</td></tr>` : "";
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:600px;margin:0 auto;padding:20px;color:#14213a;">
<h2 style="color:#0b1a30;border-bottom:4px solid #ff5a36;padding-bottom:10px;">Your appraisal request was received</h2>
<p>Hi ${escapeHtml(d.name)},</p>
<p>Thank you for your request. Here is what happens next:</p>
<ol style="padding-left:20px;">
<li style="margin:6px 0;">Brian Ward reviews your request and emails a secure invoice, along with any questions.</li>
<li style="margin:6px 0;">Pay the invoice and send your photos.</li>
<li style="margin:6px 0;">${d.rush ? "<strong>The 24-hour clock starts when both payment and photos are in.</strong> It runs seven days a week, weekends and holidays included." : "Your appraisal is delivered within 5&ndash;10 business days after payment and photos."}</li>
</ol>
<p style="margin:22px 0;"><a href="${escapeHtml(d.uploadUrl)}" style="background:#ff5a36;color:#fff;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:bold;">Upload your photos now</a></p>
<p style="font-size:14px;color:#55657d;">Or simply reply to this email with the photos attached.</p>
<h3 style="color:#55657d;margin-top:24px;">What you sent</h3>
<table style="width:100%;border-collapse:collapse;background:#f6f8fc;border-radius:6px;">
${row("Service", d.serviceLabel)}${row("Property", d.fullAddress)}${row("Purpose", d.purposeLabel)}${row("Effective date", d.dateLabel)}${row("Deadline", d.deadline)}${row("Notes", d.message)}
</table>
<p style="margin-top:24px;">Thank you,<br><strong>Brian Ward</strong><br>${BRAND} &mdash; 24-hour desktop appraisals<br>California Certified Residential Real Estate Appraiser, License AR036053<br><a href="${SITE_URL}" style="color:#2456f5;">${SITE_URL.replace("https://", "")}</a></p>
<p style="margin-top:28px;padding-top:14px;border-top:1px solid #ddd;font-size:13px;color:#888;">This is an automatic confirmation. You do not need to submit the form again.</p>
</body></html>`;
}

function formatDate(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value).trim());
  if (!m) return String(value);
  const months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  const month = months[Number(m[2]) - 1];
  return month ? `${month} ${Number(m[3])}, ${m[1]}` : String(value);
}
function escapeHtml(str) {
  return String(str == null ? "" : str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
