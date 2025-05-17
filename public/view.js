/**
 * View note page functionality
 * Handles note retrieval, decryption, and display
 */
document.addEventListener('DOMContentLoaded', async () => {
  const loadingDiv = document.getElementById('loading');
  const confirmViewDiv = document.getElementById('confirmView');
  const confirmViewBtn = document.getElementById('confirmViewBtn');
  const noteContentDiv = document.getElementById('noteContent');
  const errorMessageDiv = document.getElementById('errorMessage');
  const decryptedMessageDiv = document.getElementById('decryptedMessage');
  const attachmentContainer = document.getElementById('attachmentContainer');
  const attachmentView = document.getElementById('attachmentView');
  const noteDateElement = document.getElementById('noteDate');
  const hasAttachmentElement = document.getElementById('hasAttachment');
  
  // Store the note data for later use (after confirmation)
  let noteData = null;
  let noteAttachment = null;
  
  // Parse URL parameters and hash
  const urlParams = new URLSearchParams(window.location.search);
  const noteId = urlParams.get('id');
  
  // The decryption key is stored in the URL fragment (after the #)
  const decryptionKey = window.location.hash.substring(1);
  
  // If either the note ID or decryption key is missing, show an error
  if (!noteId || !decryptionKey) {
    showErrorState('Invalid link. Missing note ID or decryption key.');
    return;
  }
  
  try {
    // First, just fetch the metadata without retrieving or deleting the note
    // This uses our new endpoint that just checks existence
    const metaResponse = await fetch(`${API_BASE_URL}/api/note/meta/${noteId}`);
    
    if (!metaResponse.ok) {
      if (metaResponse.status === 404) {
        showErrorState('This note has already been viewed or has expired.');
      } else {
        showErrorState('Failed to verify the note. Please check the URL and try again.');
      }
      return;
    }
    
    // Store the metadata for displaying info before confirmation
    const metadata = await metaResponse.json();
    
    // Show confirmation screen with note metadata
    loadingDiv.style.display = 'none';
    
    // Format the creation date from metadata
    const creationDate = new Date(metadata.created_at || Date.now());
    
    // Sanitize date display
    window.securityUtils.safeSetTextContent(noteDateElement, creationDate.toLocaleString());
    
    // Show if the note has an attachment (safe content)
    window.securityUtils.safeSetTextContent(hasAttachmentElement, metadata.hasAttachment ? 'Yes' : 'No');
    
    // Show the confirmation screen
    confirmViewDiv.classList.remove('hidden');
    
    // Set up the confirmation button handler
    confirmViewBtn.addEventListener('click', async () => {
      try {
        // Show loading while retrieving and decrypting
        confirmViewDiv.classList.add('hidden');
        loadingDiv.style.display = 'block';
        loadingDiv.querySelector('p').textContent = 'Retrieving and decrypting your note...';
        
        // NOW we actually fetch the full note, which will also delete it from the server
        const response = await fetch(`${API_BASE_URL}/api/note/${noteId}`);
        
        if (!response.ok) {
          if (response.status === 404) {
            showErrorState('This note has already been viewed or has expired.');
          } else {
            showErrorState('Failed to retrieve the note. Please check the URL and try again.');
          }
          return;
        }
        
        // Store the data for decryption
        noteData = await response.json();
        
        // Decrypt the message
        const decryptedMessage = await decryptMessage(noteData.encryptedMessage, decryptionKey);
        
        // Display the decrypted message with sanitization
        // Use our sanitization utilities to prevent XSS
        window.securityUtils.safeSetTextContent(decryptedMessageDiv, decryptedMessage);
        
        // Handle attachment if present
        if (noteData.hasAttachment && noteData.attachment) {
          try {
            // Decrypt the attachment
            const decryptedFile = await decryptFile(noteData.attachment, decryptionKey);
            
            // Sanitize the filename before display
            const sanitizedFileName = window.securityUtils.sanitizeContent(decryptedFile.name);
            const sanitizedFileType = window.securityUtils.sanitizeContent(decryptedFile.type);
            
            // Create and append file preview/download with sanitized values
            const filePreview = createFilePreview(
              decryptedFile.data, 
              sanitizedFileName, 
              sanitizedFileType
            );
            
            // Clear any existing content for safety
            attachmentView.innerHTML = '';
            attachmentView.appendChild(filePreview);
            attachmentContainer.classList.remove('hidden');
          } catch (attachmentError) {
            console.error('Error processing attachment:', attachmentError);
            // Still show the message even if attachment fails
          }
        }
        
        // Show the content
        loadingDiv.style.display = 'none';
        noteContentDiv.classList.remove('hidden');
        
        // Clear the URL hash to remove the key from the browser history
        history.replaceState(null, null, window.location.pathname + window.location.search);
      }
      catch (decryptError) {
        console.error('Decryption error:', decryptError);
        showErrorState('Failed to decrypt the message. The link may be corrupted.');
      }
    });
  } catch (error) {
    console.error('Error retrieving note:', error);
    showErrorState('An error occurred while retrieving the note.');
  }
  
  /**
   * Shows the error state UI
   * @param {string} message - The error message to display
   */
  function showErrorState(message) {
    const errorText = document.querySelector('#errorMessage p');
    
    // Sanitize error message to prevent XSS
    window.securityUtils.safeSetTextContent(errorText, message);
    
    loadingDiv.style.display = 'none';
    confirmViewDiv.classList.add('hidden');
    errorMessageDiv.classList.remove('hidden');
  }
});
