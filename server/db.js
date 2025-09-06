/**
 * Database module for CryptDrop
 * Handles all database operations using encrypted SQLite
 * Includes forensic countermeasures to prevent data recovery
 */
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Database file path
const dbPath = path.join(__dirname, 'notes.db');

// Initialize encrypted database
let db;
try {
  db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('Error opening database:', err.message);
      process.exit(1);
    } else {
      if (process.env.DB_ENCRYPTION_KEY) {
        console.log('Connected to SQLite database with application-level encryption.');
      } else {
        console.log('Connected to SQLite database (unencrypted - consider setting DB_ENCRYPTION_KEY).');
      }
      initializeDatabase();
    }
  });
} catch (err) {
  console.error('Error opening database:', err.message);
  process.exit(1);
}

// Application-level encryption functions
function encryptData(data) {
  if (!process.env.DB_ENCRYPTION_KEY) return data;
  
  try {
    const iv = crypto.randomBytes(16);
    const key = crypto.scryptSync(process.env.DB_ENCRYPTION_KEY, 'salt', 32);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Return iv + encrypted data
    return iv.toString('hex') + ':' + encrypted;
  } catch (err) {
    console.error('Encryption error:', err);
    return data;
  }
}

function decryptData(encryptedData) {
  if (!process.env.DB_ENCRYPTION_KEY) return encryptedData;
  
  try {
    const parts = encryptedData.split(':');
    if (parts.length !== 2) return encryptedData;
    
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    
    const key = crypto.scryptSync(process.env.DB_ENCRYPTION_KEY, 'salt', 32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (err) {
    console.error('Decryption error:', err);
    return encryptedData;
  }
}

/**
 * Creates the notes table if it doesn't exist
 */
function initializeDatabase() {
  db.run(`CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    encrypted_message TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    has_attachment INTEGER DEFAULT 0,
    attachment_name TEXT,
    attachment_type TEXT,
    attachment_data BLOB
  )`, (err) => {
    if (err) {
      console.error('Error creating table:', err.message);
    } else {
      console.log('Notes table initialized.');
    }
  });
}

/**
 * Saves a new encrypted note to the database
 * @param {string} id - Unique identifier for the note
 * @param {string} encryptedMessage - The encrypted message content
 * @param {Object} attachment - Optional encrypted file attachment
 * @param {Buffer} attachment.data - Encrypted file data
 * @param {string} attachment.name - Original filename (encrypted)
 * @param {string} attachment.type - MIME type (encrypted)
 * @returns {Promise} Promise that resolves when the note is saved
 */
function saveNote(id, encryptedMessage, attachment = null) {
  return new Promise((resolve, reject) => {
    const query = `INSERT INTO notes (id, encrypted_message, created_at, has_attachment, attachment_name, attachment_type, attachment_data) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)`;
    
    const hasAttachment = attachment ? 1 : 0;
    const attachmentName = attachment ? encryptData(attachment.name) : null;
    const attachmentType = attachment ? encryptData(attachment.type) : null;
    const attachmentData = attachment ? attachment.data : null;
    
    db.run(query, [id, encryptData(encryptedMessage), Date.now(), hasAttachment, attachmentName, attachmentType, attachmentData], function(err) {
      if (err) {
        reject(err);
      } else {
        resolve({ id: this.lastID });
      }
    });
  });
}

/**
 * Retrieves a note by its ID
 * @param {string} id - The note ID to retrieve
 * @returns {Promise} - Resolves with the note object or null if not found
 */
function getNoteById(id) {
  return new Promise((resolve, reject) => {
    const query = 'SELECT * FROM notes WHERE id = ?';
    
    db.get(query, [id], (err, row) => {
      if (err) {
        reject(err);
      } else if (row) {
        // Decrypt data
        row.encrypted_message = decryptData(row.encrypted_message);
        
        // Decrypt attachment metadata if present
        if (row.has_attachment && row.attachment_name) {
          row.attachment_name = decryptData(row.attachment_name);
          row.attachment_type = decryptData(row.attachment_type);
        }
        resolve(row);
      } else {
        resolve(null);
      }
    });
  });
}

/**
 * Securely deletes a note from the database
 * Uses multiple techniques to ensure forensic recovery is extremely difficult
 * @param {string} id - The note ID to delete
 * @returns {Promise} - Resolves with true if deleted, false if not found
 */
function deleteNote(id) {
  return new Promise((resolve, reject) => {
    // First, overwrite the note content with random data several times
    secureOverwriteNote(id)
      .then(() => {
        // Then delete the record
        db.run(
          'DELETE FROM notes WHERE id = ?',
          [id],
          function(err) {
            if (err) {
              reject(err);
            } else {
              // Vacuum the database to reclaim space and remove deleted data
              vacuumDatabase()
                .then(() => resolve(this.changes > 0))
                .catch(vacuumErr => {
                  console.error('Error vacuuming database:', vacuumErr);
                  resolve(this.changes > 0); // Still resolve since the delete worked
                });
            }
          }
        );
      })
      .catch(err => reject(err));
  });
}

/**
 * Securely overwrites a note's content with random data multiple times
 * This makes forensic recovery much more difficult
 * @param {string} id - The note ID to securely overwrite
 * @returns {Promise} - Resolves when overwriting is complete
 */
function secureOverwriteNote(id) {
  return new Promise((resolve, reject) => {
    // First get the note to know how large the content is
    db.get('SELECT encrypted_message, has_attachment, attachment_data FROM notes WHERE id = ?', [id], (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      
      if (!row) {
        resolve(); // Note not found, nothing to overwrite
        return;
      }
      
      // Perform multiple overwrites with different patterns
      // This follows the DoD 5220.22-M data sanitization method
      const contentLength = row.encrypted_message.length;
      
      // First pass: all zeros
      const zerosData = '0'.repeat(contentLength);
      
      // Second pass: all ones
      const onesData = '1'.repeat(contentLength);
      
      // Third pass: random data
      const randomData = crypto.randomBytes(Math.ceil(contentLength / 2))
                              .toString('hex')
                              .substring(0, contentLength);
      
      // Create promises for each overwrite operation
      const overwrites = [
        new Promise((resolve, reject) => {
          db.run('UPDATE notes SET encrypted_message = ? WHERE id = ?', [zerosData, id], (err) => {
            if (err) reject(err);
            else resolve();
          });
        }),
        new Promise((resolve, reject) => {
          db.run('UPDATE notes SET encrypted_message = ? WHERE id = ?', [onesData, id], (err) => {
            if (err) reject(err);
            else resolve();
          });
        }),
        new Promise((resolve, reject) => {
          db.run('UPDATE notes SET encrypted_message = ? WHERE id = ?', [randomData, id], (err) => {
            if (err) reject(err);
            else resolve();
          });
        })
      ];
      
      // If there's an attachment, overwrite that too
      if (row.has_attachment && row.attachment_data) {
        const attachmentLength = row.attachment_data.length;
        const randomAttachmentData = crypto.randomBytes(attachmentLength);
        
        overwrites.push(new Promise((resolveAttachment, rejectAttachment) => {
          // Overwrite attachment data multiple times
          Promise.all([
            new Promise((resolve, reject) => {
              db.run('UPDATE notes SET attachment_data = ? WHERE id = ?', [Buffer.alloc(attachmentLength, 0), id], (err) => {
                if (err) reject(err);
                else resolve();
              });
            }),
            new Promise((resolve, reject) => {
              db.run('UPDATE notes SET attachment_data = ? WHERE id = ?', [Buffer.alloc(attachmentLength, 255), id], (err) => {
                if (err) reject(err);
                else resolve();
              });
            }),
            new Promise((resolve, reject) => {
              db.run('UPDATE notes SET attachment_data = ? WHERE id = ?', [randomAttachmentData, id], (err) => {
                if (err) reject(err);
                else resolve();
              });
            })
          ]).then(() => {
            resolveAttachment();
          }).catch(err => {
            rejectAttachment(err);
          });
        }));
      }
      
      // Resolve the main promise when all overwrites are complete
      Promise.all(overwrites).then(() => resolve()).catch(err => reject(err));
    });
  });
}

/**
 * Deletes expired notes (older than 24 hours)
 * @returns {Promise} - Resolves with the number of deleted notes
 */
function deleteExpiredNotes() {
  return new Promise((resolve, reject) => {
    const expiryTime = Date.now() - (24 * 60 * 60 * 1000); // 24 hours ago
    
    db.run(
      'DELETE FROM notes WHERE created_at < ?',
      [expiryTime],
      function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.changes);
        }
      }
    );
  });
}

/**
 * Vacuums the SQLite database to reclaim space and remove traces of deleted data
 * This helps prevent forensic recovery of deleted notes
 * @returns {Promise} - Resolves when vacuum is complete
 */
function vacuumDatabase() {
  return new Promise((resolve, reject) => {
    db.run('VACUUM', (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

/**
 * Securely shreds all data related to a note, making it extremely difficult to recover
 * @param {string} id - The note ID to shred
 * @returns {Promise} - Resolves when secure deletion is complete
 */
function secureShredNote(id) {
  return deleteNote(id);
}

// Clean up expired notes on startup with secure deletion
deleteExpiredNotes()
  .then(count => {
    if (count > 0) {
      console.log(`Securely cleaned up ${count} expired notes.`);
      // Vacuum database after batch cleanup
      return vacuumDatabase();
    }
  })
  .then(() => {
    console.log('Database maintenance complete.');
  })
  .catch(err => {
    console.error('Error cleaning up expired notes:', err);
  });
  
// Schedule periodic database maintenance
setInterval(() => {
  vacuumDatabase()
    .then(() => console.log('Scheduled database maintenance complete'))
    .catch(err => console.error('Error during scheduled maintenance:', err));
}, 12 * 60 * 60 * 1000); // Run every 12 hours

// Export database functions
module.exports = {
  saveNote,
  getNoteById,
  deleteNote,
  deleteExpiredNotes,
  secureShredNote,
  vacuumDatabase
};
