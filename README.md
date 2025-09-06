# CryptDrop

A secure web-based private note sharing service with client-side encryption and forensic countermeasures. This application allows users to create secure notes that can only be viewed once and automatically expire after 24 hours.

## Features

### Core Functionality
- **Client-side encryption** using the Web Crypto API (AES-GCM)
- **One-time readable notes** (deleted after viewing)
- **Automatic expiration** after 24 hours
- **Secure file attachments** with client-side encryption (up to 15MB)
- **Confirmation step** before viewing notes to prevent accidental deletion
- **Advanced forensic countermeasures** to prevent data recovery
- **No user accounts** or login required

### Security Features
- **Database encryption at rest** using AES-256-CBC
- **Auto-generated secure keys** for database, session, and CSRF protection
- **Protection against zip bombs** and malicious compressed files
- **Magic byte detection** for compressed file types
- **Rate limiting** with configurable parameters
- **Comprehensive audit logging** with 30-day retention
- **XSS protection** with dynamic CSP nonces
- **Input validation** and sanitization

### User Experience
- **Professional error handling** with visual feedback and retry functionality
- **Form validation** with field-specific error messages
- **Toast notifications** for user feedback
- **Dark mode** by default with light mode support
- **Responsive design** for mobile and desktop
- **Comprehensive documentation** (Privacy Policy, FAQ, Forensic Countermeasures, Changelog)

## Security Architecture

### Client-Side Security
- **AES-GCM encryption** in the browser using Web Crypto API
- **Encryption keys never sent** to the server
- **URL fragment storage** (after #) - not transmitted to server
- **Memory clearing** after encryption/decryption operations
- **Content sanitization** to prevent XSS attacks

### Server-Side Security
- **Dual-layer encryption**: Client-side + Database-level
- **AES-256-CBC database encryption** with auto-generated keys
- **Secure key management** via environment variables
- **Multiple data overwrites** for secure deletion (DoD 5220.22-M standard)
- **Database vacuuming** after deletion operations
- **Protection against compression attacks** (zip bombs, decompression bombs)
- **HTTP security headers** via Helmet.js
- **Rate limiting** to prevent abuse
- **Audit logging** for security monitoring

## Technology Stack

- **Frontend**: HTML, CSS, and vanilla JavaScript
- **Backend**: Node.js with Express
- **Database**: SQLite

## Installation

1. Clone the repository:
```bash
git clone https://github.com/egomaniac9023/CryptDrop.git
cd CryptDrop
```

2. Install dependencies:
```bash
npm install
```

3. Environment Setup:
The application will automatically generate secure encryption keys on first run. These are stored in a `.env` file:
- `DB_ENCRYPTION_KEY` - 32-byte hex key for database encryption
- `SESSION_SECRET` - 64-byte hex key for session management  
- `CSRF_SECRET` - 32-byte hex key for CSRF protection

Optional environment variables:
```bash
PORT=3000                           # Server port (default: 3000)
RATE_LIMIT_WINDOW_MS=900000        # Rate limit window (default: 15 minutes)
RATE_LIMIT_MAX_REQUESTS=100        # Max requests per window (default: 100)
CREATE_NOTE_LIMIT_MAX=10           # Max note creations per window (default: 10)
CORS_ORIGINS=http://localhost:3000 # Allowed CORS origins
AUDIT_LOG_DIR=./server/logs        # Audit log directory
AUDIT_LOG_RETENTION_DAYS=30        # Log retention period
```

## Running the Application

Start the server:
```bash
npm start
```

The application will be available at: http://localhost:3000

### Production Deployment
For production environments:
1. Set `NODE_ENV=production`
2. Configure appropriate CORS origins
3. Use a reverse proxy (nginx/Apache) with HTTPS
4. Set up log rotation for audit logs
5. Monitor disk space for database and logs

## How It Works

### Note Creation Process
1. **Client-side encryption**: Message is encrypted locally using AES-GCM
2. **Key generation**: Random encryption key generated in browser
3. **Server transmission**: Only encrypted data sent to server
4. **Database storage**: Encrypted data stored with additional AES-256-CBC layer
5. **Link generation**: URL created with note ID and encryption key in fragment

### Note Viewing Process
1. **Retrieval**: Encrypted note fetched using ID from URL
2. **Decryption**: Key from URL fragment decrypts message locally
3. **Secure deletion**: Note immediately deleted from server with forensic countermeasures
4. **Memory clearing**: Encryption keys cleared from browser memory

### Security Measures
- **Dual encryption**: Client-side AES-GCM + Server-side AES-256-CBC
- **Zero-knowledge**: Server never sees unencrypted content
- **Forensic protection**: Multiple overwrites + database vacuuming
- **Attack prevention**: Zip bomb detection, rate limiting, input validation

## Dependencies

### Core Dependencies
```json
{
  "express": "^4.18.2",
  "sqlite3": "^5.1.6",
  "dotenv": "^16.3.1",
  "helmet": "^7.0.0",
  "express-rate-limit": "^6.8.1",
  "express-validator": "^7.0.1",
  "nanoid": "^4.0.2"
}
```

### Security Dependencies
- **helmet**: HTTP security headers
- **express-rate-limit**: Request rate limiting
- **express-validator**: Input validation and sanitization
- **crypto** (Node.js built-in): Server-side encryption

## File Structure

```
/CryptDrop
  /public
    index.html          # Create note page
    view.html           # View note page  
    style.css           # Shared styles with error handling UI
    script.js           # Shared JavaScript utilities
    create.js           # Create note functionality
    view.js             # View note functionality
    sanitize.js         # Content sanitization utilities
    error-handler.js    # Comprehensive error handling system
    privacy-policy.html # Privacy policy documentation
    faq.html           # Frequently asked questions
    forensics.html     # Forensic countermeasures documentation
    changelog.html     # Version history and changes
  /server
    index.js           # Express server with security middleware
    db.js              # Database operations with encryption
    /logs              # Audit logs directory (auto-created)
  .env                 # Environment variables (auto-generated)
  .gitignore          # Git ignore patterns
  package.json        # Dependencies and scripts
  README.md           # This documentation
```

## Security Audit & Compliance

### Implemented Security Standards
- **DoD 5220.22-M**: Secure data deletion standard
- **OWASP Top 10**: Protection against common web vulnerabilities
- **CSP Level 3**: Content Security Policy with nonces
- **HTTP Security Headers**: Comprehensive header protection

### Audit Logging
All security-relevant events are logged:
- Note creation/deletion events
- Failed upload attempts (zip bombs, oversized files)
- Rate limiting violations
- Input validation failures
- Authentication attempts (if implemented)

Logs are automatically rotated and retained for 30 days by default.

## License

This project is open source and available under the MIT License.
