'use strict';

const express = require('express');
const cors = require('cors');
const { securityHeaders, apiLimiter, authLimiter, passwordResetLimiter } = require('./middleware/security');

const { env } = require('./config/env');
const routes = require('./routes');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  const allowedOrigins = env.FRONTEND_URL.split(',').map((o) => o.trim());
  app.use(
    cors({
      origin: allowedOrigins,
      credentials: true,
    })
  );

  // Security headers
  app.use(securityHeaders);

  // Global rate limiting
  app.use(apiLimiter);

  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Stricter rate limiting for auth endpoints
  app.use('/api/v1/auth/login', authLimiter);
  app.use('/api/v1/auth/forgot-password', authLimiter);
  app.use('/api/v1/auth/reset-password', authLimiter);
  app.use('/api/v1/auth/verify-otp', authLimiter);
  app.use('/api/v1/auth/verify-reset-token', authLimiter);
  app.use('/api/v1/auth/forgot-password', passwordResetLimiter);
  app.use('/api/v1/auth/reset-password', passwordResetLimiter);

  app.use('/api/v1', routes);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
