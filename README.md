# Evolution Cloud Site

Site Astro pour Evolution Cloud.

## Commandes

```sh
npm install
npm run dev
npm run build
npm run preview
```

## Formulaire de contact

Le site est configuré en `output: 'server'` avec l’adaptateur Node.
La route `/api/contact` gère l’envoi du formulaire côté serveur.

Variables à configurer:

```bash
CONTACT_TO_EMAIL=
CONTACT_FROM_EMAIL=
SMTP_URL=
SMTP_HOST=
SMTP_PORT=
SMTP_SECURE=
SMTP_USER=
SMTP_PASS=
PUBLIC_TURNSTILE_SITE_KEY=
TURNSTILE_SECRET_KEY=
CLOUDFLARE_TURNSTILE_SECRET_KEY=
```
