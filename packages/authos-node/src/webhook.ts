import * as crypto from 'crypto';
import type { WebhookVerifyOptions } from './types';

const DEFAULT_TOLERANCE = 5 * 60 * 1000; // 5 minutes

/**
 * Error class for webhook verification failures
 */
export class WebhookVerificationError extends Error {
  constructor(
    message: string,
    public readonly code: string
  ) {
    super(message);
    this.name = 'WebhookVerificationError';
  }
}

/**
 * Parse the webhook signature header
 * Format: t=timestamp,v1=signature
 */
function parseSignatureHeader(header: string): { timestamp: number; signatures: string[] } {
  const parts = header.split(',');
  let timestamp = 0;
  const signatures: string[] = [];

  for (const part of parts) {
    const [key, value] = part.split('=', 2);
    if (key === 't') {
      timestamp = parseInt(value, 10);
    } else if (key === 'v1') {
      signatures.push(value);
    }
  }

  return { timestamp, signatures };
}

/**
 * Compute the expected signature for a webhook payload
 */
function computeSignature(timestamp: number, payload: string, secret: string): string {
  const signedPayload = `${timestamp}.${payload}`;
  return crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Verify a webhook signature from AuthOS
 *
 * @param signatureHeader - The signature header value (e.g., from 'X-AuthOS-Signature' or 'Webhook-Signature')
 * @param payload - The raw request body as a string
 * @param secret - The webhook signing secret
 * @param options - Verification options
 * @returns true if signature is valid
 * @throws WebhookVerificationError if verification fails
 *
 * @example
 * ```typescript
 * app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
 *   const signature = req.headers['x-authos-signature'] as string;
 *   const payload = req.body.toString();
 *
 *   try {
 *     verifyWebhookSignature(signature, payload, process.env.WEBHOOK_SECRET!);
 *     // Process webhook...
 *     res.status(200).send('OK');
 *   } catch (err) {
 *     res.status(400).send('Invalid signature');
 *   }
 * });
 * ```
 */
export function verifyWebhookSignature(
  signatureHeader: string,
  payload: string,
  secret: string,
  options: WebhookVerifyOptions = {}
): boolean {
  const { tolerance = DEFAULT_TOLERANCE } = options;

  if (!signatureHeader) {
    throw new WebhookVerificationError('Missing signature header', 'MISSING_SIGNATURE');
  }

  if (!payload) {
    throw new WebhookVerificationError('Missing payload', 'MISSING_PAYLOAD');
  }

  if (!secret) {
    throw new WebhookVerificationError('Missing webhook secret', 'MISSING_SECRET');
  }

  const { timestamp, signatures } = parseSignatureHeader(signatureHeader);

  if (!timestamp) {
    throw new WebhookVerificationError('Missing timestamp in signature', 'MISSING_TIMESTAMP');
  }

  if (signatures.length === 0) {
    throw new WebhookVerificationError('No signatures found in header', 'NO_SIGNATURES');
  }

  // Verify timestamp is within tolerance
  const now = Date.now();
  const timestampMs = timestamp * 1000;

  if (Math.abs(now - timestampMs) > tolerance) {
    throw new WebhookVerificationError(
      'Webhook timestamp is outside tolerance window',
      'TIMESTAMP_EXPIRED'
    );
  }

  // Compute expected signature
  const expectedSignature = computeSignature(timestamp, payload, secret);

  // Check if any of the provided signatures match
  const isValid = signatures.some((sig) => secureCompare(sig, expectedSignature));

  if (!isValid) {
    throw new WebhookVerificationError('Invalid webhook signature', 'INVALID_SIGNATURE');
  }

  return true;
}

/**
 * Create a webhook signature for testing purposes
 *
 * @param payload - The payload to sign
 * @param secret - The signing secret
 * @param timestamp - Optional timestamp (defaults to current time)
 * @returns The signature header value
 */
export function createWebhookSignature(
  payload: string,
  secret: string,
  timestamp?: number
): string {
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const signature = computeSignature(ts, payload, secret);
  return `t=${ts},v1=${signature}`;
}
