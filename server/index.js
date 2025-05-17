/**
 * Main server file for CryptDrop
 * Sets up Express server with routes for creating and retrieving notes
 */
const express = require('express');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const db = require('./db');
const crypto = require('crypto');
const xss = require('xss');
const sanitizeHtml = require('sanitize-html');
const { check, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { nanoid } = require('nanoid');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Define rate limits to prevent brute force and DoS attacks
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429, 
    message: 'Too many requests, please try again after 15 minutes'
  }
});

// More strict rate limit for note creation to prevent abuse
const createNoteLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // limit each IP to 20 note creations per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429, 
    message: 'Too many notes created. Please try again after an hour.'
  }
});

// Set security-related constants
const CSRF_SECRET = crypto.randomBytes(32).toString('hex');
const SESSION_SECRET = crypto.randomBytes(32).toString('hex');

// Security middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 
    ['https://yourdomain.com'] : ['http://localhost:3000'],
  methods: ['GET', 'POST'],
  credentials: true,
  maxAge: 86400 // 24 hours in seconds
}));

// Generate CSP nonce at startup
const CSP_NONCE = crypto.randomBytes(16).toString('base64');

// Apply Helmet with enhanced CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Simplified for this app
      styleSrc: ["'self'", "'unsafe-inline'"], // Necessary for basic styling
      imgSrc: ["'self'", 'data:'], // Allow data: for simple embedded images
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      fontSrc: ["'self'", 'data:'],
      manifestSrc: ["'self'"],
      workerSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  // Other Helmet defaults
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hsts: process.env.NODE_ENV === 'production' ? 
    { maxAge: 15552000, includeSubDomains: true } : false,
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'no-referrer' },
  xssFilter: true
}));

// Middleware to set CSP nonce in res.locals for templates
app.use((req, res, next) => {
  res.locals.nonce = CSP_NONCE;
  next();
});

// Apply rate limiting
app.use('/api/', apiLimiter);
app.use('/api/note', createNoteLimiter);

// Cookie parser for potential future auth features
app.use(cookieParser());

// Add security headers to prevent caching of sensitive data
app.use((req, res, next) => {
  // Prevent browsers from caching sensitive pages
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  
  // Additional security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  
  // Protection against clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  next();
});

// Validate and sanitize all incoming JSON
app.use(express.json({ 
  limit: '50mb',
  verify: (req, res, buf, encoding) => {
    try {
      // Basic JSON syntax validation
      JSON.parse(buf);
    } catch (e) {
      // If JSON is not valid, reject the request
      res.status(400).json({ error: 'Invalid JSON in request body' });
      throw new Error('Invalid JSON');
    }
  }
}));

// Middleware to sanitize all inputs to protect against XSS
app.use((req, res, next) => {
  if (req.body) {
    // Only sanitize string fields, not binary data or encrypted content
    // We're careful to avoid sanitizing encrypted data, which could break it
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string' && 
          key !== 'encryptedMessage' && 
          !(req.body.attachment && key === 'data')) {
        // Use both XSS and sanitize-html for thorough protection
        req.body[key] = sanitizeHtml(xss(req.body[key]));
      }
    });
  }
  
  if (req.query) {
    Object.keys(req.query).forEach(key => {
      if (typeof req.query[key] === 'string') {
        req.query[key] = sanitizeHtml(xss(req.query[key]));
      }
    });
  }
  
  if (req.params) {
    Object.keys(req.params).forEach(key => {
      if (typeof req.params[key] === 'string') {
        req.params[key] = sanitizeHtml(xss(req.params[key]));
      }
    });
  }
  
  next();
});

// Serve static files with security headers
app.use(express.static(path.join(__dirname, '../public'), {
  etag: false,
  lastModified: false,
  setHeaders: (res, path) => {
    // Apply strict CSP on HTML files
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Content-Security-Policy', "default-src 'self'");
    }
  }
}));

// Serve static files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// API Routes

/**
 * Create a new note
 * Receives encrypted message, optional attachment, and stores with a unique ID
 * With added validation and security checks
 */
app.post('/api/note', [
  // Input validation using express-validator
  check('encryptedMessage')
    .exists().withMessage('Encrypted message is required')
    .isString().withMessage('Encrypted message must be a string')
    .isLength({ min: 10, max: 1024 * 1024 }).withMessage('Encrypted message size out of bounds')
    .trim(),
  
  // Validate attachment if present
  check('attachment.name')
    .optional()
    .isString().withMessage('Attachment name must be a string')
    .isLength({ max: 1024 }).withMessage('Attachment name too long')
    .trim(),
  
  check('attachment.type')
    .optional()
    .isString().withMessage('Attachment type must be a string')
    .isLength({ max: 128 }).withMessage('Attachment type too long')
    .trim(),
  
  check('attachment.data')
    .optional()
    .isString().withMessage('Attachment data must be base64 encoded')
    .isLength({ max: 20 * 1024 * 1024 }).withMessage('Attachment too large')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }
    
    const { encryptedMessage, attachment } = req.body;
    
    // Additional validation
    if (!encryptedMessage) {
      return res.status(400).json({ error: 'Encrypted message is required' });
    }
    
    // Generate a unique ID for the note with enough entropy
    // nanoid(10) gives ~57 bits of entropy, which is adequate for this use case
    const id = nanoid(10);
    
    // Add some randomness to the ID to further prevent guessing
    const randomSuffix = crypto.randomBytes(2).toString('hex');
    const secureId = `${id}${randomSuffix}`;
    
    // Check for file attachment
    let attachmentData = null;
    if (attachment && attachment.data && attachment.name && attachment.type) {
      try {
        // Validate attachment size (limit to 15MB)
        const dataBuffer = Buffer.from(attachment.data, 'base64');
        if (dataBuffer.length > 15 * 1024 * 1024) {
          return res.status(400).json({ error: 'Attachment too large (max 15MB)' });
        }
        
        // Validate that the data is properly base64 encoded
        if (attachment.data.length % 4 !== 0) {
          return res.status(400).json({ error: 'Invalid attachment data encoding' });
        }
        
        // Validate MIME type format
        if (!/^[\w-]+\/[\w.-]+$/i.test(attachment.type)) {
          return res.status(400).json({ error: 'Invalid attachment MIME type' });
        }
        
        attachmentData = {
          data: dataBuffer,
          name: attachment.name, // Already sanitized by middleware
          type: attachment.type  // Already sanitized by middleware
        };
      } catch (encodingError) {
        return res.status(400).json({ error: 'Invalid attachment data' });
      }
    }
    
    // Save the note to the database
    await db.saveNote(secureId, encryptedMessage, attachmentData);
    
    // Set security headers specifically for this response
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
    });
    
    res.status(201).json({ id: secureId });
  } catch (error) {
    console.error('Error creating note:', error);
    res.status(500).json({ error: 'Failed to create note' });
  }
});

/**
 * Get note metadata to verify a note exists without retrieving or deleting it
 * This allows confirming existence before viewing
 */
app.get('/api/note/meta/:id', [
  // Validate ID parameter
  check('id')
    .exists().withMessage('Note ID is required')
    .isString().withMessage('Note ID must be a string')
    .isLength({ min: 10, max: 20 }).withMessage('Invalid note ID length')
    .matches(/^[A-Za-z0-9_-]+$/).withMessage('Note ID contains invalid characters')
    .trim()
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(404).json({ error: 'Note not found or already viewed' });
    }
    
    const { id } = req.params;
    
    // Clean up expired notes first
    await db.deleteExpiredNotes();
    
    // Get the note with sanitized parameters but only check existence
    const sanitizedId = sanitizeHtml(xss(id));
    const note = await db.getNoteById(sanitizedId);
    
    if (!note) {
      // Even for non-existent notes, introduce random delay to prevent timing attacks
      const randomDelay = crypto.randomInt(50, 200);
      await new Promise(resolve => setTimeout(resolve, randomDelay));
      return res.status(404).json({ error: 'Note not found or already viewed' });
    }
    
    // Check if note is expired (24 hours)
    const expiryTime = note.created_at + (24 * 60 * 60 * 1000);
    if (Date.now() > expiryTime) {
      // Delete expired notes
      await db.secureShredNote(id);
      return res.status(404).json({ error: 'Note has expired' });
    }
    
    // Only return metadata, not the actual content
    res.json({
      id: note.id,
      hasAttachment: note.has_attachment === 1,
      created_at: note.created_at
    });
  } catch (error) {
    console.error('Error checking note:', error);
    res.status(500).json({ error: 'Failed to check note' });
  }
});

/**
 * Get a note by ID
 * Retrieves the encrypted note and deletes it from the database
 * With enhanced security and validation
 */
app.get('/api/note/:id', [
  // Validate ID parameter
  check('id')
    .exists().withMessage('Note ID is required')
    .isString().withMessage('Note ID must be a string')
    .isLength({ min: 10, max: 20 }).withMessage('Invalid note ID length')
    .matches(/^[A-Za-z0-9_-]+$/).withMessage('Note ID contains invalid characters')
    .trim()
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // Don't reveal exactly what's wrong with the ID
      return res.status(404).json({ error: 'Note not found or already viewed' });
    }
    
    // Rate limit individual IP-note combinations to prevent brute force
    const noteIpKey = `${req.ip}-note-${req.params.id}`;
    const noteFetchLimit = getNoteFetchRateLimit(noteIpKey);
    if (noteFetchLimit.exceeded) {
      return res.status(429).json({ 
        error: 'Too many attempts to access this note. Please try again later.' 
      });
    }
    
    const { id } = req.params;
    
    // Clean up expired notes first
    await db.deleteExpiredNotes();
    
    // Get the note with sanitized parameters
    const sanitizedId = sanitizeHtml(xss(id));
    const note = await db.getNoteById(sanitizedId);
    
    if (!note) {
      // Even for non-existent notes, introduce random delay to prevent timing attacks
      const randomDelay = crypto.randomInt(50, 200);
      await new Promise(resolve => setTimeout(resolve, randomDelay));
      return res.status(404).json({ error: 'Note not found or already viewed' });
    }
    
    // Check if note is expired (24 hours)
    const expiryTime = note.created_at + (24 * 60 * 60 * 1000);
    if (Date.now() > expiryTime) {
      // Securely delete expired notes to prevent forensic recovery
      await db.secureShredNote(id);
      return res.status(404).json({ error: 'Note has expired' });
    }
    
    // Prepare response before deletion to minimize data existence window
    const responseData = {
      id: note.id,
      encryptedMessage: note.encrypted_message,
      hasAttachment: note.has_attachment === 1
    };
    
    // If there's an attachment, include it in the response
    if (note.has_attachment === 1 && note.attachment_data) {
      responseData.attachment = {
        name: note.attachment_name,
        type: note.attachment_type,
        data: note.attachment_data.toString('base64')
      };
    }
    
    // Securely delete the note to prevent forensic recovery
    await db.secureShredNote(id);
    
    // Log deletion but never log content details
    console.log(`Note ${id} securely deleted after viewing`);
    
    // Add random delay to prevent timing attacks
    const randomDelay = crypto.randomInt(30, 100);
    await new Promise(resolve => setTimeout(resolve, randomDelay));
    
    // Send the response we prepared before deletion
    res.json(responseData);
  } catch (error) {
    console.error('Error retrieving note:', error);
    res.status(500).json({ error: 'Failed to retrieve note' });
  }
});

// Schedule regular database maintenance
setInterval(async () => {
  try {
    const count = await db.deleteExpiredNotes();
    if (count > 0) {
      console.log(`Scheduled cleanup: securely deleted ${count} expired notes`);
      await db.vacuumDatabase();
    }
  } catch (error) {
    console.error('Error during scheduled cleanup:', error);
  }
}, 60 * 60 * 1000); // Run hourly

// Graceful shutdown to ensure proper database cleanup
process.on('SIGINT', async () => {
  console.log('Graceful shutdown initiated...');
  try {
    await db.vacuumDatabase();
    console.log('Database vacuumed successfully');
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown cleanup:', error);
    process.exit(1);
  }
});

// Simple in-memory rate limit tracker
const rateLimitTracker = {};

// Function to check if note fetch rate limit is exceeded
function getNoteFetchRateLimit(key) {
  const now = Date.now();
  if (!rateLimitTracker[key]) {
    rateLimitTracker[key] = {
      count: 1,
      firstAccess: now,
      lastAccess: now
    };
    return { exceeded: false };
  }
  
  const record = rateLimitTracker[key];
  
  // Reset if window expired (15 minutes)
  if (now - record.firstAccess > 15 * 60 * 1000) {
    record.count = 1;
    record.firstAccess = now;
    record.lastAccess = now;
    return { exceeded: false };
  }
  
  // Check if limit exceeded
  if (record.count >= 5) {
    return { exceeded: true };
  }
  
  // Update count and last access
  record.count += 1;
  record.lastAccess = now;
  return { exceeded: false };
}

// Simple error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'An unexpected error occurred'
  });
});

// Handle unmatched routes
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found'
  });
});

// Start the server with enhanced security
const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`View the app at http://localhost:${PORT}/index.html`);
  console.log('Forensic countermeasures active: Secure deletion enabled');
  console.log('XSS and security protections enabled');
});

// Implement proper server shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
  });
});
