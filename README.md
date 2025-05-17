# CryptDrop

A secure web-based private note sharing service with client-side encryption and forensic countermeasures. This application allows users to create secure notes that can only be viewed once and automatically expire after 24 hours.

## Features

- Client-side encryption using the Web Crypto API
- One-time readable notes (deleted after viewing)
- Automatic expiration after 24 hours
- Secure file attachments with client-side encryption
- Confirmation step before viewing notes to prevent accidental deletion
- Advanced forensic countermeasures to prevent data recovery
- Dark mode by default
- Simple and clean UI
- No user accounts or login required
- Comprehensive documentation (Privacy Policy, FAQ, Forensic Countermeasures)

## Security

- Messages are encrypted in the browser using AES-GCM
- The encryption key is never sent to the server
- The server only stores: `id`, `encrypted_message`, and `created_at`
- Keys are passed in the URL fragment (after the #), which is not sent to the server

## Technology Stack

- **Frontend**: HTML, CSS, and vanilla JavaScript
- **Backend**: Node.js with Express
- **Database**: SQLite

## Installation

1. Clone the repository:
```
git clone https://github.com/egomaniac9023/CryptDrop.git
cd CryptDrop
```

2. Install dependencies:
```
npm install
```

## Running the Application

Start the server:
```
npm start
```

The application will be available at: http://localhost:3000

## How It Works

1. When a user creates a note:
   - The message is encrypted locally in the browser
   - A random encryption key is generated
   - The encrypted message is sent to the server and stored with a unique ID
   - A link is generated with the ID and the encryption key (in the URL fragment)

2. When a user views a note:
   - The ID from the URL is used to retrieve the encrypted message from the server
   - The key from the URL fragment is used to decrypt the message locally
   - The note is immediately deleted from the server after retrieval
   - The key is removed from the browser's URL bar to prevent it from being stored in history

## File Structure

```
/cryptdrop
  /public
    index.html       # Create note page
    view.html        # View note page
    style.css        # Shared styles
    script.js        # Shared JavaScript utilities
    create.js        # Create note functionality
    view.js          # View note functionality
  /server
    index.js         # Express server setup and routes
    db.js            # Database operations
    notes.db         # SQLite database (created on first run)
  package.json
  README.md
```

## License

This project is open source and available under the MIT License.
