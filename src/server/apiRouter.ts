import express, { Request, Response } from 'express';
import {
  evaluateAndStartQuestions,
  processAnswerAndGetNextQuestion,
  generateDebriefWithGemini,
  transcribeAudioWithGemini
} from './geminiService.ts';
import {
  createRateLimiter,
  validatePitchPayload,
  validateAnswerPayload,
  validateTranscribePayload
} from './securityMiddleware.ts';

export const apiRouter = express.Router();

// Specific rate limiters per route to prevent abuse and API exhaustion
const pitchLimiter = createRateLimiter({ windowMs: 60 * 1000, maxRequests: 25, name: 'pitch' });
const answerLimiter = createRateLimiter({ windowMs: 60 * 1000, maxRequests: 40, name: 'answer' });
const debriefLimiter = createRateLimiter({ windowMs: 60 * 1000, maxRequests: 20, name: 'debrief' });
const transcribeLimiter = createRateLimiter({ windowMs: 60 * 1000, maxRequests: 15, name: 'transcribe' });

// 1. Initial pitch evaluation & Start Turn-by-Turn Questioning
apiRouter.post('/pitch', pitchLimiter, validatePitchPayload, async (req: Request, res: Response) => {
  try {
    const { pitch } = req.body;
    const result = await evaluateAndStartQuestions(pitch);
    res.json(result);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown evaluation error';
    console.error('[SECURITY LOG - PITCH ERROR]:', message);
    res.status(500).json({ error: 'Failed to evaluate pitch at this time. Please try again.' });
  }
});

// 2. Process an answered question and advance to the next Shark
apiRouter.post('/answer-question', answerLimiter, validateAnswerPayload, async (req: Request, res: Response) => {
  try {
    const {
      pitch,
      answeredQuestion,
      userAnswerText,
      currentStatuses,
      currentScores,
      activeOffers
    } = req.body;

    const result = await processAnswerAndGetNextQuestion(
      pitch,
      answeredQuestion,
      userAnswerText,
      currentStatuses || {},
      currentScores || {},
      activeOffers || []
    );
    res.json(result);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown answer processing error';
    console.error('[SECURITY LOG - ANSWER ERROR]:', message);
    res.status(500).json({ error: 'Failed to process answer at this time. Please try again.' });
  }
});

// 3. Post-pitch debrief & Pitch Doctor scorecard
apiRouter.post('/debrief', debriefLimiter, async (req: Request, res: Response) => {
  try {
    const { pitch, history, outcome } = req.body;
    if (!pitch || typeof pitch !== 'object') {
      return res.status(400).json({ error: 'Valid pitch data is required for debrief generation.' });
    }

    const result = await generateDebriefWithGemini(
      pitch,
      Array.isArray(history) ? history : [],
      outcome || { dealClosed: false }
    );
    res.json(result);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown debrief error';
    console.error('[SECURITY LOG - DEBRIEF ERROR]:', message);
    res.status(500).json({ error: 'Failed to generate pitch debrief report.' });
  }
});

// 4. Voice Audio Transcription fallback route via Gemini
apiRouter.post('/transcribe', transcribeLimiter, validateTranscribePayload, async (req: Request, res: Response) => {
  try {
    const { audioData, mimeType } = req.body;
    const transcript = await transcribeAudioWithGemini(audioData, mimeType || 'audio/webm');
    res.json({ transcript });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Transcription error';
    console.error('[SECURITY LOG - TRANSCRIBE ERROR]:', message);
    res.status(500).json({ error: 'Audio transcription failed. Please use text input or try again.' });
  }
});

