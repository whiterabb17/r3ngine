const LABEL_MAP: Record<string, string> = {
  'detected-facebook-oauth': 'Facebook OAuth Token',
  'detected-github-oauth': 'GitHub OAuth Token',
  'detected-google-oauth': 'Google OAuth Token',
  'detected-twitter-oauth': 'Twitter OAuth Token',
  'generic-api-key': 'Generic API Key',
  'detected-aws-account-id': 'AWS Account ID',
  'detected-aws-access-key': 'AWS Access Key',
  'detected-aws-secret-key': 'AWS Secret Key',
  'stripe-secret-key': 'Stripe Secret Key',
  'stripe-publishable-key': 'Stripe Publishable Key',
  'slack-api-token': 'Slack API Token',
  'slack-webhook-url': 'Slack Webhook URL',
  'github-personal-access-token': 'GitHub Personal Access Token',
  'gitlab-personal-access-token': 'GitLab Personal Access Token',
  'sendgrid-api-token': 'SendGrid API Token',
  'twilio-api-key': 'Twilio API Key',
  'jwt-token': 'JWT Token',
  'private-key': 'Private Key',
  'rsa-private-key': 'RSA Private Key',
  'ssh-private-key': 'SSH Private Key',
  'password-in-url': 'Password in URL',
  'hardcoded-password': 'Hardcoded Password',
  'hardcoded-secret': 'Hardcoded Secret',
  'basic-auth-credentials': 'Basic Auth Credentials',
  'firebase-api-key': 'Firebase API Key',
  'heroku-api-key': 'Heroku API Key',
  'mailchimp-api-key': 'Mailchimp API Key',
  'paypal-braintree-access-token': 'PayPal Braintree Token',
  'shopify-access-token': 'Shopify Access Token',
  'twitch-api-key': 'Twitch API Key',
};

const STRIP_PREFIXES = new Set([
  'usr', 'src', 'github', 'semgrep_rules', 'rules', 'app', 'p',
  'semgrep_vulnerability_temp', 'semgrep_secret_temp', 'temp',
]);

const BOILERPLATE = new Set(['detected', 'generic', 'security']);

export function formatSecretType(raw: string): string {
  if (!raw) return '';

  // Strip dot-path prefixes
  const parts = raw.split('.');
  let start = 0;
  while (start < parts.length && STRIP_PREFIXES.has(parts[start].toLowerCase())) {
    start++;
  }
  const cleanParts = parts.slice(start);
  if (!cleanParts.length) return raw;

  // Deduplicate trailing repeat
  if (cleanParts.length >= 2 && cleanParts[cleanParts.length - 1].toLowerCase() === cleanParts[cleanParts.length - 2].toLowerCase()) {
    cleanParts.pop();
  }

  const slug = cleanParts[cleanParts.length - 1];

  // Lookup first
  if (LABEL_MAP[slug]) return LABEL_MAP[slug];

  // Smart parse fallback
  const words = slug.replace(/-/g, ' ').split(' ').filter(w => !BOILERPLATE.has(w.toLowerCase()));
  return words.map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') || slug;
}

export interface SecretCategory {
  label: string;
  colorKey: 'error' | 'warning' | 'info' | 'default';
}

export function getSecretCategory(label: string): SecretCategory {
  const lower = label.toLowerCase();
  if (['private key', 'rsa', 'ssh key'].some(kw => lower.includes(kw))) {
    return { label: 'Private Key', colorKey: 'error' };
  }
  if (['password', 'credential', 'auth', 'login', 'hardcoded secret'].some(kw => lower.includes(kw))) {
    return { label: 'Credential', colorKey: 'error' };
  }
  if (['oauth', 'access token'].some(kw => lower.includes(kw))) {
    return { label: 'OAuth Token', colorKey: 'info' };
  }
  if (['api key', 'api token', 'access key'].some(kw => lower.includes(kw))) {
    return { label: 'API Key', colorKey: 'warning' };
  }
  return { label: 'Secret', colorKey: 'default' };
}
