import type { APIRoute } from 'astro';
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
const CONTACT_WINDOW_MS = 10 * 60 * 1000;
const CONTACT_LIMIT_PER_WINDOW = 6;

type ContactBucket = {
  count: number;
  resetAt: number;
};

const contactBuckets = new Map<string, ContactBucket>();

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

function isValidEmail(value: string) {
  if (value.length > MAX_EMAIL_LENGTH) {
    return false;
  }

  if (value.includes('\r') || value.includes('\n')) {
    return false;
  }

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isSameOrigin(request: Request, url: URL) {
  const origin = request.headers.get('origin');
  const referer = request.headers.get('referer');

  if (origin) {
    return origin === url.origin;
  }

  if (referer) {
    try {
      return new URL(referer).origin === url.origin;
    } catch {
      return false;
    }
  }

  return false;
}

function getClientKey(request: Request) {
  const forwardedFor = request.headers.get('x-forwarded-for');
  if (forwardedFor) {
    return forwardedFor.split(',')[0]?.trim() || 'unknown';
  }

  return request.headers.get('x-real-ip')?.trim() || 'unknown';
}

function isRateLimited(request: Request) {
  const key = getClientKey(request);
  const now = Date.now();
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

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export const POST: APIRoute = async ({ request, url }) => {
  if (!isSameOrigin(request, url)) {
    return Response.redirect(new URL('/contact?error=origin', url), 303);
  }

  if (isRateLimited(request)) {
    return Response.redirect(new URL('/contact?error=rate', url), 303);
  }

  const formData = await request.formData();
  const honeypot = normalize(formData.get('website'));
  const rawName = normalize(formData.get('name'));
  const rawCompany = normalize(formData.get('company'));
  const rawEmail = normalize(formData.get('email'));
  const rawPhone = normalize(formData.get('phone'));
  const rawMessage = normalize(formData.get('message'));

  if (honeypot) {
    return Response.redirect(new URL('/contact?error=spam', url), 303);
  }

  if (
    rawName.length > MAX_FIELD_LENGTH ||
    rawCompany.length > MAX_FIELD_LENGTH ||
    rawEmail.length > MAX_FIELD_LENGTH ||
    rawPhone.length > MAX_FIELD_LENGTH ||
    rawMessage.length > MAX_FIELD_LENGTH
  ) {
    return Response.redirect(new URL('/contact?error=invalid', url), 303);
  }

  const name = stripDangerousControlChars(rawName);
  const company = stripDangerousControlChars(rawCompany);
  const email = stripDangerousControlChars(rawEmail).toLowerCase();
  const phone = stripDangerousControlChars(rawPhone);
  const message = sanitizeMultiline(rawMessage);

  if (!name || !email || !message) {
    return Response.redirect(new URL('/contact?error=missing', url), 303);
  }

  if (
    name.length > MAX_NAME_LENGTH ||
    company.length > MAX_COMPANY_LENGTH ||
    email.length > MAX_EMAIL_LENGTH ||
    phone.length > MAX_PHONE_LENGTH ||
    message.length > MAX_MESSAGE_LENGTH
  ) {
    return Response.redirect(new URL('/contact?error=invalid', url), 303);
  }

  if (!isValidEmail(email)) {
    return Response.redirect(new URL('/contact?error=invalid', url), 303);
  }

  const transport = getSmtpTransport();

  if (!transport) {
    return Response.redirect(new URL('/contact?error=smtp', url), 303);
  }

  const subject = `Nouveau message de contact - ${name}`;
  const text = [
    'Nouveau message reçu via le formulaire de contact',
    '',
    `Nom: ${name}`,
    `Entreprise: ${company || '-'}`,
    `Courriel: ${email}`,
    `Téléphone: ${phone || '-'}`,
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

    return Response.redirect(new URL('/contact?sent=1', url), 303);
  } catch {
    return Response.redirect(new URL('/contact?error=send', url), 303);
  }
};
