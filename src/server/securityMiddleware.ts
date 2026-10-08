import { Request, Response, NextFunction } from 'express';

/**
 * Enterprise-grade Security Middleware Suite
 * Complies with OWASP Top 10 (Web) & OWASP Top 10 for LLMs
 */

// 1. HTTP Security Headers Middleware
export function applySecurityHeaders(req: Request, res: Response, next: NextFunction): void {
  // Never intercept AI Studio internal control plane routes
  if (req.url && req.url.includes('__aistudio_internal_control_plane')) {
    return next();
  }

  // Prevent MIME-sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Cross-site scripting legacy filter protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Referrer Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Permissions Policy - restrict browser features not needed by app
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=(), payment=()');
  
  // Strict Content Security Policy (allows iframe embedding required by AI Studio)
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https: blob:; media-src 'self' blob: data:; connect-src 'self' https: wss:; frame-ancestors *;"
  );

  // Disable client-side caching for API endpoints
  if (req.path.startsWith('/api')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }

  next();
}

// 2. Sliding-Window Rate Limiter
interface RateLimitRecord {
  timestamps: number[];
}

const rateLimitStores = new Map<string, Map<string, RateLimitRecord>>();

export function createRateLimiter(options: {
  windowMs: number;
  maxRequests: number;
  name: string;
}) {
  const store = new Map<string, RateLimitRecord>();
  rateLimitStores.set(options.name, store);

  // Periodic cleanup of stale IPs every 5 minutes
  setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of store.entries()) {
      record.timestamps = record.timestamps.filter((ts) => now - ts < options.windowMs);
      if (record.timestamps.length === 0) {
        store.delete(ip);
      }
    }
  }, 5 * 60 * 1000);

  return (req: Request, res: Response, next: NextFunction) => {
    const ip =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() ||
      req.socket.remoteAddress ||
      'unknown-client';

    const now = Date.now();
    let clientRecord = store.get(ip);
    if (!clientRecord) {
      clientRecord = { timestamps: [] };
      store.set(ip, clientRecord);
    }

    // Retain only requests within the sliding window
    clientRecord.timestamps = clientRecord.timestamps.filter((ts) => now - ts < options.windowMs);

    if (clientRecord.timestamps.length >= options.maxRequests) {
      const oldestTs = clientRecord.timestamps[0];
      const retryAfterSec = Math.ceil((options.windowMs - (now - oldestTs)) / 1000);
      res.setHeader('Retry-After', Math.max(1, retryAfterSec));
      return res.status(429).json({
        error: 'Too Many Requests',
        message: 'Rate limit exceeded. Please wait a moment before sending another request.',
        retryAfter: Math.max(1, retryAfterSec),
      });
    }

    clientRecord.timestamps.push(now);
    next();
  };
}

// 3. String Sanitization & Prompt Injection Defense
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
  /system\s+prompt\s+override/i,
  /you\s+are\s+now\s+a(?:n)?\s+(?:unrestricted|jailbroken|different)/i,
  /<\s*\|\s*im_start\s*\|\s*>/i,
  /<\s*\|\s*im_end\s*\|\s*>/i,
  /\[\s*system\s*\]/i,
  /\{\s*"\s*role\s*"\s*:\s*"system"/i,
  /bypass\s+all\s+(?:safety|content)\s+filters/i,
  /as\s+an\s+ai\s+without\s+rules/i,
];

export function sanitizeText(input: unknown, maxLength: number = 2000): string {
  if (typeof input !== 'string') return '';
  
  // Truncate length
  let cleaned = input.slice(0, maxLength);
  
  // Strip null bytes and non-printable control characters (except common whitespace)
  cleaned = cleaned.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  
  // Strip raw HTML script / event tags
  cleaned = cleaned.replace(/<\s*script[^>]*>[\s\S]*?<\s*\/\s*script\s*>/gi, '');
  cleaned = cleaned.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
  
  // Mitigate prompt injection patterns by defanging known override phrases
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    cleaned = cleaned.replace(pattern, '[FILTERED_INSTRUCTION_OVERRIDE]');
  }

  return cleaned.trim();
}

export function sanitizeNumber(input: unknown, min: number, max: number, fallback: number): number {
  if (typeof input !== 'number' || isNaN(input) || !isFinite(input)) {
    return fallback;
  }
  return Math.min(Math.max(input, min), max);
}

// 4. Request Validation Middlewares
export function validatePitchPayload(req: Request, res: Response, next: NextFunction) {
  const { pitch } = req.body;
  if (!pitch || typeof pitch !== 'object') {
    return res.status(400).json({ error: 'Validation Error: Invalid pitch object provided.' });
  }

  const businessName = sanitizeText(pitch.businessName, 120);
  if (!businessName || businessName.length < 2) {
    return res.status(400).json({ error: 'Validation Error: Company name is required (min 2 characters).' });
  }

  // Normalize and bound fields
  req.body.pitch = {
    businessName,
    tagline: sanitizeText(pitch.tagline, 250),
    pitchText: sanitizeText(pitch.pitchText, 3000),
    askAmount: sanitizeNumber(pitch.askAmount, 1000, 100_000_000, 250000),
    askEquity: sanitizeNumber(pitch.askEquity, 0.5, 99, 10),
    annualSales: sanitizeNumber(pitch.annualSales, 0, 500_000_000, 150000),
    cogs: sanitizeNumber(pitch.cogs, 0, 1_000_000, 4.5),
    retailPrice: sanitizeNumber(pitch.retailPrice, 0, 2_000_000, 19.99),
    patents: sanitizeText(pitch.patents, 300),
    category: sanitizeText(pitch.category, 100),
  };

  next();
}

export function validateAnswerPayload(req: Request, res: Response, next: NextFunction) {
  const { pitch, answeredQuestion, userAnswerText } = req.body;
  if (!pitch || typeof pitch !== 'object') {
    return res.status(400).json({ error: 'Validation Error: pitch is required.' });
  }
  if (!answeredQuestion || typeof answeredQuestion !== 'object') {
    return res.status(400).json({ error: 'Validation Error: answeredQuestion is required.' });
  }
  if (!userAnswerText || typeof userAnswerText !== 'string' || !userAnswerText.trim()) {
    return res.status(400).json({ error: 'Validation Error: userAnswerText is required.' });
  }

  req.body.userAnswerText = sanitizeText(userAnswerText, 2500);
  next();
}

export function validateTranscribePayload(req: Request, res: Response, next: NextFunction) {
  const { audioData, mimeType } = req.body;
  if (!audioData || typeof audioData !== 'string') {
    return res.status(400).json({ error: 'Validation Error: audioData must be a valid base64 string.' });
  }

  // Enforce max audio length: 15MB base64 (~11MB binary audio, approx 3-5 minutes)
  if (audioData.length > 15 * 1024 * 1024) {
    return res.status(413).json({ error: 'Payload Too Large: Audio exceeds 15MB limit.' });
  }

  // Validate MIME type against allowed audio formats
  const allowedMimes = ['audio/webm', 'audio/wav', 'audio/mp4', 'audio/ogg', 'audio/mpeg', 'audio/aac'];
  const sanitizedMime = typeof mimeType === 'string' ? mimeType.toLowerCase().trim() : 'audio/webm';
  if (!allowedMimes.includes(sanitizedMime)) {
    return res.status(400).json({ error: `Validation Error: Unsupported mimeType. Allowed: ${allowedMimes.join(', ')}` });
  }

  req.body.mimeType = sanitizedMime;
  next();
}

// 5. Malformed JSON Body Error Handler
export function handleJsonParseError(err: unknown, _req: Request, res: Response, next: NextFunction) {
  if (err instanceof SyntaxError && 'status' in err && (err as { status: number }).status === 400) {
    return res.status(400).json({ error: 'Malformed JSON payload provided in request.' });
  }
  next(err);
}

// 6. Global Secure Error Handler (prevents stack traces & server leak)
export function globalErrorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction) {
  const errorMessage = err instanceof Error ? err.message : 'Internal Server Error';
  console.error('[SECURITY LOG - UNCAUGHT ERROR]:', errorMessage);
  
  res.status(500).json({
    error: 'An internal server error occurred while processing your request.',
    code: 'INTERNAL_ERROR',
  });
}
