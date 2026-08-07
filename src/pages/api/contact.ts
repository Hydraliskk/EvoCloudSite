import type { APIRoute } from 'astro';
import { createHash, randomUUID } from 'node:crypto';
import nodemailer from 'nodemailer';

if (typeof process.loadEnvFile === 'function') {
  try {
    process.loadEnvFile();
  } catch {
    // Ignore missing or unreadable .env files; deployment environments may inject vars differently.
  }
}

const CONTACT_EMAIL = process.env.CONTACT_TO_EMAIL ?? 'info@evolutioncloud.net';
const MAX_NAME_LENGTH = 100;
const MAX_COMPANY_LENGTH = 120;
const MAX_EMAIL_LENGTH = 254;
const MAX_PHONE_LENGTH = 40;
const MAX_MESSAGE_LENGTH = 4000;
const MAX_FIELD_LENGTH = 5000;
const MAX_TURNSTILE_TOKEN_LENGTH = 2048;
const MAX_REQUEST_BODY_BYTES = 128 * 1024;
const CONTACT_WINDOW_MS = 10 * 60 * 1000;
const CONTACT_LIMIT_PER_WINDOW = 6;
const MAX_RATE_LIMIT_BUCKETS = 10_000;
const RATE_LIMIT_CLEANUP_INTERVAL_MS = 60 * 1000;
const TURNSTILE_SITE_KEY = process.env.PUBLIC_TURNSTILE_SITE_KEY ?? '';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY ?? process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY ?? '';
const TURNSTILE_ALLOWED_HOSTNAMES = new Set(
  (process.env.TURNSTILE_ALLOWED_HOSTNAMES ?? '')
    .split(',')
    .map((hostname) => hostname.trim().toLowerCase().replace(/\.$/, ''))
    .filter(Boolean)
);
const ALLOW_TURNSTILE_DEVELOPMENT_BYPASS = process.env.NODE_ENV === 'development';
// Enable only after confirming the front proxy overwrites X-Forwarded-For from clients.
const TRUST_PROXY_CLIENT_IP = process.env.TRUST_PROXY_CLIENT_IP === 'true';

type ContactBucket = {
  count: number;
  resetAt: number;
};

const contactBuckets = new Map<string, ContactBucket>();
let lastRateLimitCleanup = 0;

function getSmtpTransport() {
  const smtpUrl = process.env.SMTP_URL;

  if (smtpUrl) {
    return nodemailer.createTransport(smtpUrl);
  }

  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT ?? 587);
  const secure = (process.env.SMTP_SECURE ?? 'false').toLowerCase() === 'true';
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    return null;
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: {
      user,
      pass
    }
  });
}

function normalize(value: FormDataEntryValue | null) {
  return typeof value === 'string' ? value.trim() : '';
}

function stripDangerousControlChars(value: string) {
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/\r/g, ' ')
    .replace(/\n/g, ' ')
    .trim();
}

function sanitizeMultiline(value: string) {
  return value
    .replace(/\u0000/g, '')
    .replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .trim();
}

function sanitizeSingleLine(value: string) {
  return value
    .replace(/\u0000/g, '')
    .replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function isValidEmail(value: string) {
  if (value.length > MAX_EMAIL_LENGTH) {
    return false;
  }

  if (value.includes('\r') || value.includes('\n')) {
    return false;
  }

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function redirectToContact(params: Record<string, string>) {
  const query = new URLSearchParams(params);
  return new Response(null, {
    status: 303,
    headers: {
      Location: `/contact?${query.toString()}`,
      'Cache-Control': 'no-store'
    }
  });
}

function cleanupRateLimitBuckets(now: number) {
  if (now - lastRateLimitCleanup < RATE_LIMIT_CLEANUP_INTERVAL_MS && contactBuckets.size < MAX_RATE_LIMIT_BUCKETS) {
    return;
  }

  for (const [key, bucket] of contactBuckets) {
    if (bucket.resetAt <= now) {
      contactBuckets.delete(key);
    }
  }

  while (contactBuckets.size >= MAX_RATE_LIMIT_BUCKETS) {
    const oldestKey = contactBuckets.keys().next().value as string | undefined;
    if (!oldestKey) break;
    contactBuckets.delete(oldestKey);
  }

  lastRateLimitCleanup = now;
}

function isRateLimited(clientAddress: string) {
  if (!TRUST_PROXY_CLIENT_IP) {
    return false;
  }

  const key = createHash('sha256').update(clientAddress || 'unknown').digest('hex');
  const now = Date.now();
  cleanupRateLimitBuckets(now);
  const bucket = contactBuckets.get(key);

  if (!bucket || bucket.resetAt <= now) {
    contactBuckets.set(key, { count: 1, resetAt: now + CONTACT_WINDOW_MS });
    return false;
  }

  if (bucket.count >= CONTACT_LIMIT_PER_WINDOW) {
    return true;
  }

  bucket.count += 1;
  return false;
}

type FormDataReadResult =
  | { ok: true; formData: FormData }
  | { ok: false; reason: 'invalid' | 'too-large' | 'type' };

type TurnstileVerificationResult =
  | { ok: true }
  | { ok: false; reason: 'captcha' | 'captcha-config' };

async function readBoundedFormData(request: Request): Promise<FormDataReadResult> {
  const contentType = request.headers.get('content-type') ?? '';
  const mediaType = contentType.split(';', 1)[0]?.trim().toLowerCase();
  if (mediaType !== 'multipart/form-data' || !/;\s*boundary=/i.test(contentType)) {
    return { ok: false, reason: 'type' };
  }

  const contentLengthHeader = request.headers.get('content-length');
  if (contentLengthHeader) {
    if (!/^\d+$/.test(contentLengthHeader)) {
      return { ok: false, reason: 'invalid' };
    }

    const contentLength = Number(contentLengthHeader);
    if (!Number.isSafeInteger(contentLength) || contentLength > MAX_REQUEST_BODY_BYTES) {
      return { ok: false, reason: 'too-large' };
    }
  }

  if (!request.body) {
    return { ok: false, reason: 'invalid' };
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      totalBytes += value.byteLength;
      if (totalBytes > MAX_REQUEST_BODY_BYTES) {
        await reader.cancel();
        return { ok: false, reason: 'too-large' };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, reason: 'invalid' };
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  const headers = new Headers(request.headers);
  headers.delete('content-length');
  headers.delete('transfer-encoding');

  try {
    const boundedRequest = new Request(request.url, {
      method: 'POST',
      headers,
      body
    });
    return { ok: true, formData: await boundedRequest.formData() };
  } catch {
    return { ok: false, reason: 'invalid' };
  }
}

async function verifyTurnstileToken(token: string, clientAddress: string): Promise<TurnstileVerificationResult> {
  if (!TURNSTILE_SITE_KEY || !TURNSTILE_SECRET_KEY || TURNSTILE_ALLOWED_HOSTNAMES.size === 0) {
    if (ALLOW_TURNSTILE_DEVELOPMENT_BYPASS) {
      return { ok: true };
    }
    return { ok: false, reason: 'captcha-config' };
  }

  if (!token || token.length > MAX_TURNSTILE_TOKEN_LENGTH) {
    return { ok: false, reason: 'captcha' };
  }

  const verificationData = new FormData();
  verificationData.set('secret', TURNSTILE_SECRET_KEY);
  verificationData.set('response', token);
  if (clientAddress) {
    verificationData.set('remoteip', clientAddress);
  }

  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: verificationData,
      signal: AbortSignal.timeout(10_000)
    });

    if (!response.ok) {
      return { ok: false, reason: 'captcha' };
    }

    const result = (await response.json()) as {
      success?: boolean;
      action?: string;
      hostname?: string;
    };
    const hostname = result.hostname?.trim().toLowerCase().replace(/\.$/, '') ?? '';
    const valid = result.success === true
      && result.action === 'contact'
      && TURNSTILE_ALLOWED_HOSTNAMES.has(hostname);
    return valid ? { ok: true } : { ok: false, reason: 'captcha' };
  } catch {
    return { ok: false, reason: 'captcha' };
  }
}

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export const POST: APIRoute = async ({ request, clientAddress }) => {
  const formDataResult = await readBoundedFormData(request);
  if (!formDataResult.ok) {
    return redirectToContact({ error: formDataResult.reason });
  }

  if (isRateLimited(clientAddress)) {
    return redirectToContact({ error: 'rate' });
  }

  const formData = formDataResult.formData;
  const honeypot = normalize(formData.get('website'));
  const rawName = normalize(formData.get('name'));
  const rawCompany = normalize(formData.get('company'));
  const rawEmail = normalize(formData.get('email'));
  const rawPhone = normalize(formData.get('phone'));
  const rawUrgency = normalize(formData.get('urgency'));
  const rawMessage = normalize(formData.get('message'));
  const rawPrivacyConsent = normalize(formData.get('privacyConsent'));
  const turnstileToken = normalize(formData.get('cf-turnstile-response'));

  if (honeypot) {
    return redirectToContact({ error: 'spam' });
  }

  if (
    rawName.length > MAX_FIELD_LENGTH ||
    rawCompany.length > MAX_FIELD_LENGTH ||
    rawEmail.length > MAX_FIELD_LENGTH ||
    rawPhone.length > MAX_FIELD_LENGTH ||
    rawUrgency.length > MAX_FIELD_LENGTH ||
    rawMessage.length > MAX_FIELD_LENGTH ||
    rawPrivacyConsent.length > MAX_FIELD_LENGTH ||
    turnstileToken.length > MAX_TURNSTILE_TOKEN_LENGTH
  ) {
    return redirectToContact({ error: 'invalid' });
  }

  const name = stripDangerousControlChars(rawName);
  const company = stripDangerousControlChars(rawCompany);
  const email = stripDangerousControlChars(rawEmail).toLowerCase();
  const phone = stripDangerousControlChars(rawPhone);
  const urgency = sanitizeSingleLine(rawUrgency).toLowerCase();
  const message = sanitizeMultiline(rawMessage);
  const urgencyLabelMap: Record<string, string> = {
    faible: 'Faible',
    moyenne: 'Moyenne',
    elevee: 'Élevée'
  };
  const urgencyLabel = urgencyLabelMap[urgency] ?? 'Non précisé';

  if (!name || !email || !message) {
    return redirectToContact({ error: 'missing' });
  }

  if (rawPrivacyConsent !== '1') {
    return redirectToContact({ error: 'consent' });
  }

  if (
    name.length > MAX_NAME_LENGTH ||
    company.length > MAX_COMPANY_LENGTH ||
    email.length > MAX_EMAIL_LENGTH ||
    phone.length > MAX_PHONE_LENGTH ||
    urgency.length > MAX_FIELD_LENGTH ||
    message.length > MAX_MESSAGE_LENGTH
  ) {
    return redirectToContact({ error: 'invalid' });
  }

  if (!isValidEmail(email)) {
    return redirectToContact({ error: 'invalid' });
  }

  const captcha = await verifyTurnstileToken(
    turnstileToken,
    TRUST_PROXY_CLIENT_IP ? clientAddress : ''
  );
  if (!captcha.ok) {
    return redirectToContact({ error: captcha.reason });
  }

  const transport = getSmtpTransport();

  if (!transport) {
    const errorId = randomUUID();
    console.error('Contact form email sending failed', {
      errorId,
      errorName: 'SmtpConfigurationError',
      errorCode: 'SMTP_CONFIG',
      timestamp: new Date().toISOString()
    });
    return redirectToContact({ error: 'send', errorId });
  }

  const subject = `Nouveau message de contact - ${name}`;
  const text = [
    'Nouveau message reçu via le formulaire de contact',
    '',
    `Nom: ${name}`,
    `Entreprise: ${company || '-'}`,
    `Courriel: ${email}`,
    `Téléphone: ${phone || '-'}`,
    `Niveau d'urgence: ${urgencyLabel}`,
    '',
    'Message:',
    message
  ].join('\n');

  const html = `
    <h2>Nouveau message reçu via le formulaire de contact</h2>
    <p><strong>Nom :</strong> ${escapeHtml(name)}</p>
    <p><strong>Entreprise :</strong> ${escapeHtml(company || '-')}</p>
    <p><strong>Courriel :</strong> ${escapeHtml(email)}</p>
    <p><strong>Téléphone :</strong> ${escapeHtml(phone || '-')}</p>
    <p><strong>Niveau d'urgence :</strong> ${escapeHtml(urgencyLabel)}</p>
    <h3>Message</h3>
    <p style="white-space: pre-wrap;">${escapeHtml(message)}</p>
  `;

  try {
    await transport.sendMail({
      from: process.env.CONTACT_FROM_EMAIL ?? `"Evolution Cloud" <${CONTACT_EMAIL}>`,
      to: CONTACT_EMAIL,
      replyTo: email,
      subject,
      text,
      html
    });

    return redirectToContact({ sent: '1' });
  } catch (error) {
    const errorInfo = error as {
      name?: string;
      code?: string;
      responseCode?: number;
    };

    const errorId = randomUUID();

    console.error('Contact form email sending failed', {
      errorId,
      errorName: errorInfo?.name,
      errorCode: errorInfo?.code,
      errorResponseCode: errorInfo?.responseCode,
      timestamp: new Date().toISOString()
    });
    return redirectToContact({ error: 'send', errorId });
  }
};

export const GET: APIRoute = async () =>
  new Response('Method Not Allowed', {
    status: 405,
    headers: {
      Allow: 'POST'
    }
  });
