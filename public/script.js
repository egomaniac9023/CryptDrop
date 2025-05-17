/**
 * Shared utility functions for the Privnote clone
 * Includes encryption/decryption functions using Web Crypto API
 * With added forensic countermeasures to prevent data recovery
 */

// Base URL for API calls
const API_BASE_URL = window.location.origin;

// Detect if the page is in view.html (to apply stricter security measures)
const isViewPage = window.location.pathname.includes('view.html');

// Prevent browser back button on view page to avoid cached content access
if (isViewPage) {
  window.history.pushState(null, '', window.location.href);
  window.addEventListener('popstate', function() {
    window.history.pushState(null, '', window.location.href);
    alert('Back navigation is disabled for security reasons.');
  });
  
  // Prevent right-click to disable save options
  document.addEventListener('contextmenu', e => e.preventDefault());
  
  // Disable keyboard shortcuts that could save content
  document.addEventListener('keydown', e => {
    // Prevent print (Ctrl+P)
    if (e.ctrlKey && e.key === 'p') {
      e.preventDefault();
    }
    // Prevent save (Ctrl+S)
    if (e.ctrlKey && e.key === 's') {
      e.preventDefault();
    }
    // Prevent view source (Ctrl+U)
    if (e.ctrlKey && e.key === 'u') {
      e.preventDefault();
    }
    // Prevent screenshots (PrintScreen) when possible
    if (e.key === 'PrintScreen') {
      // Can't fully prevent but can clear text
      setTimeout(() => {
        secureMemoryClear();
      }, 100);
    }
  });
  
  // Add page unload security to clear sensitive data
  window.addEventListener('beforeunload', () => {
    secureMemoryClear();
  });
}

/**
 * Converts an ArrayBuffer to a Base64 string
 * @param {ArrayBuffer} buffer - The buffer to convert
 * @returns {string} - Base64 encoded string
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a Base64 string to an ArrayBuffer
 * @param {string} base64 - The Base64 string to convert
 * @returns {ArrayBuffer} - The resulting ArrayBuffer
 */
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Generates a random encryption key
 * @returns {Promise<string>} - Base64 encoded encryption key
 */
async function generateEncryptionKey() {
  // Generate a random 256-bit key
  const key = await window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt', 'decrypt']
  );
  
  // Export the key
  const rawKey = await window.crypto.subtle.exportKey('raw', key);
  
  // Convert to Base64 for easy URL inclusion
  return arrayBufferToBase64(rawKey);
}

/**
 * Imports an encryption key from Base64 format
 * @param {string} keyBase64 - Base64 encoded key
 * @returns {Promise<CryptoKey>} - Imported CryptoKey object
 */
async function importEncryptionKey(keyBase64) {
  const rawKey = base64ToArrayBuffer(keyBase64);
  
  return window.crypto.subtle.importKey(
    'raw',
    rawKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a message using AES-GCM
 * @param {string} message - The plaintext message to encrypt
 * @param {string} keyBase64 - Base64 encoded encryption key
 * @returns {Promise<string>} - Base64 encoded encrypted data with IV
 */
async function encryptMessage(message, keyBase64) {
  // Import the key
  const key = await importEncryptionKey(keyBase64);
  
  // Generate a random IV (Initialization Vector)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  // Convert message to ArrayBuffer
  const encoder = new TextEncoder();
  const messageBuffer = encoder.encode(message);
  
  // Encrypt the message
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    messageBuffer
  );
  
  // Combine IV and ciphertext for storage
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  
  // Convert to Base64 for storage
  return arrayBufferToBase64(combined.buffer);
}

/**
 * Encrypts a file using AES-GCM
 * @param {File} file - The file to encrypt
 * @param {string} keyBase64 - Base64 encoded encryption key
 * @returns {Promise<Object>} - Object containing encrypted file data, name and type
 */
async function encryptFile(file, keyBase64) {
  // Import the key
  const key = await importEncryptionKey(keyBase64);
  
  // Generate a random IV (Initialization Vector)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = async (event) => {
      try {
        const fileArrayBuffer = event.target.result;
        
        // Track buffer for secure deletion later
        if (window.sensitiveBuffers) {
          window.sensitiveBuffers.push(fileArrayBuffer);
        }
        
        // Encrypt the file data
        const ciphertext = await window.crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: iv
          },
          key,
          fileArrayBuffer
        );
        
        // Combine IV and ciphertext
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(ciphertext), iv.length);
        
        // Convert to Base64
        const encryptedBase64 = arrayBufferToBase64(combined.buffer);
        
        // Encrypt the filename and type as well
        const encryptedName = await encryptMessage(file.name, keyBase64);
        const encryptedType = await encryptMessage(file.type, keyBase64);
        
        resolve({
          data: encryptedBase64,
          name: encryptedName,
          type: encryptedType,
          originalSize: file.size
        });
      } catch (error) {
        reject(error);
      }
    };
    
    reader.onerror = () => {
      reject(new Error('Error reading file'));
    };
    
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Securely clears an ArrayBuffer by overwriting with random data
 * This helps prevent memory forensics from recovering sensitive data
 * @param {ArrayBuffer} buffer - The buffer to clear
 */
function secureWipeBuffer(buffer) {
  if (!buffer) return;
  
  const view = new Uint8Array(buffer);
  
  // First overwrite with zeros
  view.fill(0);
  
  // Then overwrite with ones
  view.fill(255);
  
  // Finally overwrite with random data
  window.crypto.getRandomValues(view);
}

/**
 * Securely clears all sensitive data from memory
 * This function attempts to remove any trace of decrypted content
 */
function secureMemoryClear() {
  if (window.sensitiveBuffers && Array.isArray(window.sensitiveBuffers)) {
    // Wipe all tracked sensitive buffers
    window.sensitiveBuffers.forEach(buffer => {
      secureWipeBuffer(buffer);
    });
    window.sensitiveBuffers = [];
  }
  
  // Clear any displayed messages by replacing with warning
  const messageElements = document.querySelectorAll('.message-box');
  if (messageElements.length > 0) {
    messageElements.forEach(el => {
      el.textContent = 'Content has been securely cleared from memory for your privacy.';
      el.classList.add('error-msg');
    });
  }
  
  // Force garbage collection when possible
  if (window.gc) {
    try {
      window.gc();
    } catch (e) {
      console.log('Manual garbage collection not available');
    }
  }
  
  // Clear sensitive variables from global scope
  if (window.sensitiveVariables && Array.isArray(window.sensitiveVariables)) {
    window.sensitiveVariables.forEach(varName => {
      window[varName] = null;
    });
    window.sensitiveVariables = [];
  }
}

/**
 * Creates a download link for a file
 * @param {ArrayBuffer} data - File data
 * @param {string} filename - File name
 * @param {string} mimeType - File MIME type
 * @returns {HTMLAnchorElement} - Download link element
 */
function createDownloadLink(data, filename, mimeType) {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);
  
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.className = 'download-button';
  link.textContent = 'Download';
  
  // Clean up the URL when done
  link.addEventListener('click', () => {
    setTimeout(() => {
      URL.revokeObjectURL(url);
      // Also try to wipe the blob from memory
      if (window.sensitiveBuffers) {
        window.sensitiveBuffers.push(data);
      }
    }, 100);
  });
  
  return link;
}

/**
 * Decrypts a file
 * @param {Object} encryptedFile - Object containing encrypted file data
 * @param {string} encryptedFile.data - Base64 encoded encrypted file data
 * @param {string} encryptedFile.name - Encrypted filename
 * @param {string} encryptedFile.type - Encrypted file MIME type
 * @param {string} keyBase64 - Base64 encoded encryption key
 * @returns {Promise<Object>} - Decrypted file object with data, name, and type
 */
async function decryptFile(encryptedFile, keyBase64) {
  try {
    // Decrypt the file information
    const fileName = await decryptMessage(encryptedFile.name, keyBase64);
    const fileType = await decryptMessage(encryptedFile.type, keyBase64);
    
    // Initialize sensitive buffer tracking if not already present
    if (!window.sensitiveBuffers) {
      window.sensitiveBuffers = [];
    }
    
    // Convert from Base64
    const encryptedBuffer = base64ToArrayBuffer(encryptedFile.data);
    
    // Track buffer for secure deletion
    window.sensitiveBuffers.push(encryptedBuffer);
    
    // Extract IV (first 12 bytes) and ciphertext
    const iv = new Uint8Array(encryptedBuffer, 0, 12);
    const ciphertext = new Uint8Array(encryptedBuffer, 12);
    
    // Import the key
    const key = await importEncryptionKey(keyBase64);
    
    // Decrypt the file data
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      ciphertext
    );
    
    // Track decrypted buffer for secure deletion
    window.sensitiveBuffers.push(decryptedBuffer);
    
    return {
      data: decryptedBuffer,
      name: fileName,
      type: fileType
    };
  } catch (error) {
    console.error('Error decrypting file:', error);
    secureMemoryClear();
    throw error;
  }
}

/**
 * Creates a preview for a file
 * @param {ArrayBuffer} data - File data
 * @param {string} filename - File name
 * @param {string} mimeType - File MIME type
 * @returns {HTMLElement} - Preview element
 */
function createFilePreview(data, filename, mimeType) {
  const container = document.createElement('div');
  container.className = 'attachment-download';
  
  const infoDiv = document.createElement('div');
  infoDiv.className = 'attachment-info';
  
  // Create appropriate icon based on file type
  const iconDiv = document.createElement('div');
  iconDiv.className = 'attachment-icon';
  
  if (mimeType.startsWith('image/')) {
    iconDiv.innerHTML = '🖼️';
  } else if (mimeType.startsWith('video/')) {
    iconDiv.innerHTML = '🎬';
  } else if (mimeType.startsWith('audio/')) {
    iconDiv.innerHTML = '🎵';
  } else if (mimeType.includes('pdf')) {
    iconDiv.innerHTML = '📄';
  } else if (mimeType.includes('word') || filename.endsWith('.doc') || filename.endsWith('.docx')) {
    iconDiv.innerHTML = '📝';
  } else if (mimeType.includes('spreadsheet') || filename.endsWith('.xls') || filename.endsWith('.xlsx')) {
    iconDiv.innerHTML = '📊';
  } else if (mimeType.includes('presentation') || filename.endsWith('.ppt') || filename.endsWith('.pptx')) {
    iconDiv.innerHTML = '📽️';
  } else if (mimeType.includes('zip') || mimeType.includes('compressed')) {
    iconDiv.innerHTML = '🗜️';
  } else {
    iconDiv.innerHTML = '📎';
  }
  
  // Create file metadata display
  const metaDiv = document.createElement('div');
  metaDiv.className = 'attachment-meta';
  
  const nameSpan = document.createElement('span');
  nameSpan.className = 'attachment-name';
  nameSpan.textContent = filename;
  
  const sizeSpan = document.createElement('span');
  sizeSpan.className = 'attachment-size';
  const sizeInKB = Math.round(data.byteLength / 1024);
  sizeSpan.textContent = `${sizeInKB} KB - ${mimeType}`;
  
  metaDiv.appendChild(nameSpan);
  metaDiv.appendChild(sizeSpan);
  
  infoDiv.appendChild(iconDiv);
  infoDiv.appendChild(metaDiv);
  
  // Create download link
  const downloadLink = createDownloadLink(data, filename, mimeType);
  
  container.appendChild(infoDiv);
  container.appendChild(downloadLink);
  
  // For images, also create a preview
  if (mimeType.startsWith('image/')) {
    const imagePreview = document.createElement('div');
    imagePreview.className = 'file-preview-image';
    
    const img = document.createElement('img');
    const blob = new Blob([data], { type: mimeType });
    const url = URL.createObjectURL(blob);
    img.src = url;
    img.alt = filename;
    
    // Clean up URL when done
    img.onload = () => {
      // Let's display it for at least 5 seconds before revoking
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    };
    
    imagePreview.appendChild(img);
    container.appendChild(imagePreview);
  }
  
  return container;
}

/**
 * Decrypts a message using AES-GCM with memory protection
 * @param {string} encryptedBase64 - Base64 encoded encrypted data with IV
 * @param {string} keyBase64 - Base64 encoded encryption key
 * @returns {Promise<string>} - Decrypted plaintext message
 */
async function decryptMessage(encryptedBase64, keyBase64) {
  // Initialize sensitive buffer tracking if not already present
  if (!window.sensitiveBuffers) {
    window.sensitiveBuffers = [];
  }
  if (!window.sensitiveVariables) {
    window.sensitiveVariables = [];
  }
  
  try {
    // Import the key
    const key = await importEncryptionKey(keyBase64);
    
    // Convert from Base64
    const encryptedBuffer = base64ToArrayBuffer(encryptedBase64);
    
    // Track these buffers for secure wiping later
    window.sensitiveBuffers.push(encryptedBuffer);
    
    // Extract IV (first 12 bytes) and ciphertext
    const iv = new Uint8Array(encryptedBuffer, 0, 12);
    const ciphertext = new Uint8Array(encryptedBuffer, 12);
    
    // Decrypt the message
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      ciphertext
    );
    
    // Track the decrypted buffer for secure wiping
    window.sensitiveBuffers.push(decryptedBuffer);
    
    // Convert ArrayBuffer to string
    const decoder = new TextDecoder();
    const plaintext = decoder.decode(decryptedBuffer);
    
    // Remove decryption key from URL as soon as possible
    if (isViewPage && window.location.hash) {
      history.replaceState(null, null, window.location.pathname + window.location.search);
    }
    
    // Set an auto-destruction timer to clear memory after a period of inactivity
    if (window.memoryClearTimer) {
      clearTimeout(window.memoryClearTimer);
    }
    window.memoryClearTimer = setTimeout(() => {
      secureMemoryClear();
    }, 5 * 60 * 1000); // Clear after 5 minutes of inactivity
    
    return plaintext;
  } catch (error) {
    console.error('Decryption error:', error);
    // Clean memory even in case of error
    secureMemoryClear();
    throw error;
  }
}

/**
 * Shows an error message
 * @param {string} message - The error message to display
 */
function showError(message) {
  const errorElement = document.createElement('div');
  errorElement.className = 'error-msg';
  errorElement.textContent = message;
  document.querySelector('.card').appendChild(errorElement);
  
  // Avoid logging sensitive errors that might contain message fragments
  console.error('An error occurred');
}

// Add a listener for page visibility changes to clear memory when tab is hidden
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && isViewPage) {
    secureMemoryClear();
  }
});

// Monitor for dev tools opening (potential security threat)
(function detectDevTools() {
  const threshold = 160;
  const devtools = {
    open: false,
    orientation: null
  };
  
  const emitEvent = (state, orientation) => {
    if (state && isViewPage) {
      // If dev tools are opened on the view page, clear sensitive data immediately
      secureMemoryClear();
      showError('Developer tools detected - content has been cleared for security');
    }
  };
  
  // Check width/height differentials to detect dev tools
  setInterval(() => {
    const widthThreshold = window.innerWidth - window.outerWidth > threshold;
    const heightThreshold = window.outerHeight - window.innerHeight > threshold;
    const orientation = widthThreshold ? 'vertical' : 'horizontal';
    
    if (
      !(heightThreshold && widthThreshold) &&
      ((widthThreshold && orientation === 'vertical') ||
        (heightThreshold && orientation === 'horizontal'))
    ) {
      if (!devtools.open || devtools.orientation !== orientation) {
        emitEvent(true, orientation);
      }
      devtools.open = true;
      devtools.orientation = orientation;
    } else {
      if (devtools.open) {
        emitEvent(false, null);
      }
      devtools.open = false;
      devtools.orientation = null;
    }
  }, 500);
  
  // Also check for console opening
  if (isViewPage) {
    const consoleCheck = new Image();
    consoleCheck.src = 'data:image/png;base64,invalid';
    consoleCheck.onerror = function() {
      if (typeof console !== 'undefined' && typeof console.clear === 'function') {
        const originalClear = console.clear;
        console.clear = function() {
          secureMemoryClear();
          originalClear.call(console);
        };
      }
    };
  }
})();
