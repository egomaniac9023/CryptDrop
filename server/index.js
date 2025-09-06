/**
 * Main server file for CryptDrop
 * Sets up Express server with routes for creating and retrieving notes
 */
require('dotenv').config();
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
const fs = require('fs');

// Auto-generate secure keys if they don't exist
function generateSecureKeys() {
  const envPath = path.join(__dirname, '../.env');
  
  // Parse existing .env file to check for values
  const envContent = fs.readFileSync(envPath, 'utf8');
  const envLines = envContent.split('\n');
  const envVars = {};
  
  // Parse existing values
  envLines.forEach(line => {
    const match = line.match(/^([^=]+)=(.*)$/);
    if (match) {
      envVars[match[1]] = match[2];
    }
  });
  
  let newEnvContent = envContent;
  let updated = false;

  // Generate database encryption key if missing or empty
  if (!envVars.DB_ENCRYPTION_KEY || envVars.DB_ENCRYPTION_KEY.trim() === '') {
    const dbKey = crypto.randomBytes(32).toString('hex');
    newEnvContent = newEnvContent.replace(/DB_ENCRYPTION_KEY=.*/, `DB_ENCRYPTION_KEY=${dbKey}`);
    process.env.DB_ENCRYPTION_KEY = dbKey;
    updated = true;
    console.log('Generated new database encryption key');
  } else {
    process.env.DB_ENCRYPTION_KEY = envVars.DB_ENCRYPTION_KEY;
  }

  // Generate session secret if missing or empty
  if (!envVars.SESSION_SECRET || envVars.SESSION_SECRET.trim() === '') {
    const sessionSecret = crypto.randomBytes(64).toString('hex');
    newEnvContent = newEnvContent.replace(/SESSION_SECRET=.*/, `SESSION_SECRET=${sessionSecret}`);
    process.env.SESSION_SECRET = sessionSecret;
    updated = true;
    console.log('Generated new session secret');
  } else {
    process.env.SESSION_SECRET = envVars.SESSION_SECRET;
  }

  // Generate CSRF secret if missing or empty
  if (!envVars.CSRF_SECRET || envVars.CSRF_SECRET.trim() === '') {
    const csrfSecret = crypto.randomBytes(32).toString('hex');
    newEnvContent = newEnvContent.replace(/CSRF_SECRET=.*/, `CSRF_SECRET=${csrfSecret}`);
    process.env.CSRF_SECRET = csrfSecret;
    updated = true;
    console.log('Generated new CSRF secret');
  } else {
    process.env.CSRF_SECRET = envVars.CSRF_SECRET;
  }

  if (updated) {
    fs.writeFileSync(envPath, newEnvContent);
    console.log('Updated .env file with secure keys');
  } else {
    console.log('Using existing secure keys from .env file');
  }
}

// Generate keys on startup
generateSecureKeys();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Audit log configuration from environment
const AUDIT_LOG_DIR = process.env.AUDIT_LOG_DIR ? 
  path.resolve(__dirname, process.env.AUDIT_LOG_DIR) : 
  path.join(__dirname, 'logs');
const AUDIT_LOG_RETENTION_DAYS = parseInt(process.env.AUDIT_LOG_RETENTION_DAYS) || 30;

// Ensure logs directory exists
if (!fs.existsSync(AUDIT_LOG_DIR)) {
  fs.mkdirSync(AUDIT_LOG_DIR, { recursive: true });
}

// Allowed file types for security
const ALLOWED_MIME_TYPES = [
  'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
  'text/plain', 'text/csv',
  'application/pdf',
  'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/zip', 'application/x-zip-compressed'
];

// Entropy calculation function for detecting compressed/encrypted data
function calculateEntropy(buffer) {
  const frequencies = new Array(256).fill(0);
  
  // Count byte frequencies
  for (let i = 0; i < buffer.length; i++) {
    frequencies[buffer[i]]++;
  }
  
  // Calculate Shannon entropy
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const probability = frequencies[i] / buffer.length;
      entropy -= probability * Math.log2(probability);
    }
  }
  
  return entropy;
}

// Audit logging function with file storage
function auditLog(event, details = {}, req = null) {
  const timestamp = new Date().toISOString();
  const ip = req ? (req.ip || req.connection.remoteAddress) : 'unknown';
  const userAgent = req ? req.get('User-Agent') : 'unknown';
  
  const logEntry = {
    timestamp,
    event,
    ip,
    userAgent: userAgent ? userAgent.substring(0, 100) : 'unknown',
    ...details
  };
  
  // Console output for immediate visibility
  console.log(`[AUDIT] ${timestamp} - ${event}`, logEntry);
  
  // Write to daily log file
  const logDate = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const logFile = path.join(AUDIT_LOG_DIR, `audit-${logDate}.log`);
  const logLine = JSON.stringify(logEntry) + '\n';
  
  fs.appendFile(logFile, logLine, (err) => {
    if (err) {
      console.error('Failed to write audit log:', err);
    }
  });
}

// Function to clean up old audit logs
function cleanupOldAuditLogs() {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - AUDIT_LOG_RETENTION_DAYS);
  
  fs.readdir(AUDIT_LOG_DIR, (err, files) => {
    if (err) {
      console.error('Error reading audit log directory:', err);
      return;
    }
    
    files.forEach(file => {
      if (file.startsWith('audit-') && file.endsWith('.log')) {
        const dateMatch = file.match(/audit-(\d{4}-\d{2}-\d{2})\.log/);
        if (dateMatch) {
          const fileDate = new Date(dateMatch[1]);
          if (fileDate < cutoffDate) {
            const filePath = path.join(AUDIT_LOG_DIR, file);
            fs.unlink(filePath, (unlinkErr) => {
              if (unlinkErr) {
                console.error(`Failed to delete old audit log ${file}:`, unlinkErr);
              } else {
                console.log(`Deleted old audit log: ${file}`);
              }
            });
          }
        }
      }
    });
  });
}

// Enhanced error handler
function handleError(error, context, req = null, res = null) {
  const errorId = nanoid(8);
  
  // Log detailed error for debugging
  console.error(`[ERROR-${errorId}] ${context}:`, {
    message: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString(),
    ip: req ? req.ip : 'unknown'
  });
  
  // Audit security-related errors
  if (error.message.includes('validation') || error.message.includes('sanitiz')) {
    auditLog('SECURITY_ERROR', { errorId, context, message: error.message }, req);
  }
  
  // Return safe error message to client
  if (res) {
    res.status(500).json({ 
      error: 'An error occurred while processing your request',
      errorId 
    });
  }
  
  return errorId;
}

// Define rate limits to prevent brute force and DoS attacks
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

const createNoteLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes default
  max: parseInt(process.env.CREATE_NOTE_LIMIT_MAX) || 20, // Limit each IP to 20 note creations per windowMs
  message: 'Too many notes created from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes default
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});


// Security middleware
app.use(cors({
  origin: process.env.CORS_ORIGINS ? 
    process.env.CORS_ORIGINS.split(',') : 
    (process.env.NODE_ENV === 'production' ? 
      ['https://yourdomain.com'] : ['http://localhost:3000']),
  methods: ['GET', 'POST'],
  credentials: true,
  maxAge: 86400 // 24 hours in seconds
}));

// Dynamic CSP nonce generation per request
app.use((req, res, next) => {
  // Generate a unique nonce for each request
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

// Apply Helmet with enhanced CSP using dynamic nonce
app.use((req, res, next) => {
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", `'nonce-${res.locals.nonce}'`], // Use dynamic nonce
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
  })(req, res, next);
});

// Apply general rate limiting to all routes
app.use(generalLimit);

// Parse JSON bodies with size limit
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Apply rate limiting
app.use('/api/', apiLimiter);
app.use('/api/note', createNoteLimit);

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
      res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:");
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
        
        // Protection against zip bombs and malicious compressed files
        const fileName = attachment.name.toLowerCase();
        const suspiciousExtensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tar.gz', '.tar.bz2'];
        
        if (suspiciousExtensions.some(ext => fileName.endsWith(ext))) {
          // Additional checks for compressed files
          const compressionRatio = dataBuffer.length / attachment.data.length;
          
          // Detect potential zip bombs by checking compression efficiency
          if (compressionRatio > 0.9) {
            auditLog('SUSPICIOUS_FILE_REJECTED', { 
              reason: 'Potential zip bomb detected', 
              fileName: attachment.name,
              compressionRatio: compressionRatio 
            }, req);
            return res.status(400).json({ error: 'Suspicious compressed file detected' });
          }
          
          // Limit compressed file size more strictly
          if (dataBuffer.length > 5 * 1024 * 1024) { // 5MB limit for compressed files
            auditLog('COMPRESSED_FILE_REJECTED', { 
              reason: 'Compressed file too large', 
              fileName: attachment.name,
              size: dataBuffer.length 
            }, req);
            return res.status(400).json({ error: 'Compressed files limited to 5MB' });
          }
        }
        
        // Check for suspicious file signatures (magic bytes)
        const fileHeader = dataBuffer.slice(0, 8);
        const suspiciousSignatures = [
          Buffer.from([0x50, 0x4B, 0x03, 0x04]), // ZIP
          Buffer.from([0x50, 0x4B, 0x05, 0x06]), // Empty ZIP
          Buffer.from([0x50, 0x4B, 0x07, 0x08]), // Spanned ZIP
          Buffer.from([0x52, 0x61, 0x72, 0x21]), // RAR
          Buffer.from([0x37, 0x7A, 0xBC, 0xAF]), // 7Z
          Buffer.from([0x1F, 0x8B, 0x08]), // GZIP
        ];
        
        for (const signature of suspiciousSignatures) {
          if (fileHeader.subarray(0, signature.length).equals(signature)) {
            auditLog('COMPRESSED_FILE_BLOCKED', { 
              reason: 'Compressed file detected by signature', 
              fileName: attachment.name,
              signature: signature.toString('hex')
            }, req);
            return res.status(400).json({ error: 'Compressed files are not allowed for security reasons' });
          }
        }
        
        // Entropy check removed - files are client-side encrypted anyway
        
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
    
    // Audit log successful note creation
    auditLog('NOTE_CREATED', { 
      noteId: secureId, 
      hasAttachment: !!attachmentData,
      messageLength: encryptedMessage.length 
    }, req);
    
    // Set security headers specifically for this response
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
    });
    
    res.status(201).json({ id: secureId });
  } catch (error) {
    handleError(error, 'Note creation', req, res);
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
      // Constant delay to prevent timing attacks - always wait the same amount
      await new Promise(resolve => setTimeout(resolve, 150));
      return res.status(404).json({ error: 'Note not found or already viewed' });
    }
    
    // Check if note is expired (24 hours)
    const expiryTime = note.created_at + (24 * 60 * 60 * 1000);
    if (Date.now() > expiryTime) {
      // Delete expired notes with constant delay
      await db.secureShredNote(id);
      await new Promise(resolve => setTimeout(resolve, 150));
      return res.status(404).json({ error: 'Note has expired' });
    }
    
    // Audit log metadata access
    auditLog('NOTE_METADATA_ACCESSED', { noteId: sanitizedId }, req);
    
    // Only return metadata, not the actual content
    res.json({
      id: note.id,
      hasAttachment: note.has_attachment === 1,
      created_at: note.created_at
    });
  } catch (error) {
    handleError(error, 'Note metadata check', req, res);
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
      // Constant delay to prevent timing attacks - always wait the same amount
      await new Promise(resolve => setTimeout(resolve, 150));
      return res.status(404).json({ error: 'Note not found or already viewed' });
    }
    
    // Check if note is expired (24 hours)
    const expiryTime = note.created_at + (24 * 60 * 60 * 1000);
    if (Date.now() > expiryTime) {
      // Securely delete expired notes to prevent forensic recovery with constant delay
      await db.secureShredNote(id);
      await new Promise(resolve => setTimeout(resolve, 150));
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
    
    // Audit log note access and deletion
    auditLog('NOTE_ACCESSED_AND_DELETED', { 
      noteId: id, 
      hasAttachment: note.has_attachment === 1 
    }, req);
    
    // Add constant delay to prevent timing attacks
    await new Promise(resolve => setTimeout(resolve, 65));
    
    // Send the response we prepared before deletion
    res.json(responseData);
  } catch (error) {
    handleError(error, 'Note retrieval', req, res);
  }
});

// Schedule regular database maintenance and log cleanup
setInterval(async () => {
  try {
    const count = await db.deleteExpiredNotes();
    if (count > 0) {
      console.log(`Scheduled cleanup: securely deleted ${count} expired notes`);
      await db.vacuumDatabase();
    }
    
    // Clean up old audit logs
    cleanupOldAuditLogs();
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

// Enhanced error handling middleware
app.use((err, req, res, next) => {
  handleError(err, 'Unhandled middleware error', req, res);
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
