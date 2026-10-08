import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { apiRouter } from './src/server/apiRouter.ts';
import {
  applySecurityHeaders,
  handleJsonParseError,
  globalErrorHandler,
} from './src/server/securityMiddleware.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

// Disable fingerprinting header
app.disable('x-powered-by');

// Enforce trust proxy for secure header & IP extraction behind reverse proxies
app.set('trust proxy', 1);

// Apply strict enterprise HTTP security headers
app.use(applySecurityHeaders);

// Bounded JSON and URL-encoded body parsers with malformed payload interceptor
app.use(express.json({ limit: '16mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(handleJsonParseError);

// Health check endpoint for container orchestrators
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Protected API routes
app.use('/api', apiRouter);

// Serve static assets from dist in production
const distPath = path.resolve(__dirname, 'dist');
app.use(express.static(distPath));

// Fallback to index.html for SPA client-side routing
app.get('*', (req, res, next) => {
  if (req.url && (req.url.startsWith('/api') || req.url.includes('__aistudio_internal_control_plane'))) {
    return next();
  }
  res.sendFile(path.join(distPath, 'index.html'));
});

// Global Secure Error Handler (prevents stack traces & server leak)
app.use(globalErrorHandler);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Shark Tank Simulator running on http://0.0.0.0:${PORT}`);
});
