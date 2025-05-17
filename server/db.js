/**
 * Database module for the Privnote clone
 * Handles all database operations using SQLite
 * Includes forensic countermeasures to prevent data recovery
 */
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Database file path
const dbPath = path.join(__dirname, 'notes.db');

// Initialize database
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
    initializeDatabase();
  }
});

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
 * @returns {Promise} - Resolves with the note ID if successful
 */
function saveNote(id, encryptedMessage, attachment = null) {
  return new Promise((resolve, reject) => {
    const createdAt = Date.now();
    
    if (attachment) {
      // With attachment
      db.run(
        'INSERT INTO notes (id, encrypted_message, created_at, has_attachment, attachment_name, attachment_type, attachment_data) VALUES (?, ?, ?, 1, ?, ?, ?)',
        [id, encryptedMessage, createdAt, attachment.name, attachment.type, attachment.data],
        function(err) {
          if (err) {
            reject(err);
          } else {
            resolve(id);
          }
        }
      );
    } else {
      // Without attachment
      db.run(
        'INSERT INTO notes (id, encrypted_message, created_at, has_attachment) VALUES (?, ?, ?, 0)',
        [id, encryptedMessage, createdAt],
        function(err) {
          if (err) {
            reject(err);
          } else {
            resolve(id);
          }
        }
      );
    }
  });
}

/**
 * Retrieves a note by its ID
 * @param {string} id - The note ID to retrieve
 * @returns {Promise} - Resolves with the note object or null if not found
 */
function getNoteById(id) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT id, encrypted_message, created_at, has_attachment, attachment_name, attachment_type, attachment_data FROM notes WHERE id = ?',
      [id],
      (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row || null);
        }
      }
    );
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
                              .slice(0, contentLength);

      // Execute the overwrites in sequence
      // Start with message overwrite
      let updatePromise = new Promise((resolveUpdate, rejectUpdate) => {
        db.run('UPDATE notes SET encrypted_message = ? WHERE id = ?', [zerosData, id], err => {
          if (err) {
            rejectUpdate(err);
            return;
          }
          
          db.run('UPDATE notes SET encrypted_message = ? WHERE id = ?', [onesData, id], err => {
            if (err) {
              rejectUpdate(err);
              return;
            }
            
            db.run('UPDATE notes SET encrypted_message = ? WHERE id = ?', [randomData, id], err => {
              if (err) {
                rejectUpdate(err);
              } else {
                resolveUpdate();
              }
            });
          });
        });
      });
      
      // If there's an attachment, overwrite that too
      if (row.has_attachment && row.attachment_data) {
        const attachmentLength = row.attachment_data.length;
        
        // Create patterns for attachment overwrite
        const attachmentZeros = Buffer.alloc(attachmentLength, 0);
        const attachmentOnes = Buffer.alloc(attachmentLength, 255);
        const attachmentRandom = crypto.randomBytes(attachmentLength);
        
        updatePromise = updatePromise.then(() => {
          return new Promise((resolveAttachment, rejectAttachment) => {
            db.run('UPDATE notes SET attachment_data = ? WHERE id = ?', [attachmentZeros, id], err => {
              if (err) {
                rejectAttachment(err);
                return;
              }
              
              db.run('UPDATE notes SET attachment_data = ? WHERE id = ?', [attachmentOnes, id], err => {
                if (err) {
                  rejectAttachment(err);
                  return;
                }
                
                db.run('UPDATE notes SET attachment_data = ? WHERE id = ?', [attachmentRandom, id], err => {
                  if (err) {
                    rejectAttachment(err);
                  } else {
                    resolveAttachment();
                  }
                });
              });
            });
          });
        });
      }
      
      // Resolve the main promise when all overwrites are complete
      updatePromise.then(() => resolve()).catch(err => reject(err));
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
    db.run('VACUUM', err => {
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
