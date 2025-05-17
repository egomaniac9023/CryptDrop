/**
 * Create note page functionality
 * Handles note creation, encryption, and link generation
 */
document.addEventListener('DOMContentLoaded', () => {
  const noteForm = document.getElementById('noteForm');
  const messageInput = document.getElementById('message');
  const attachmentInput = document.getElementById('attachment');
  const fileNameDisplay = document.getElementById('fileNameDisplay');
  const fileDetails = document.getElementById('fileDetails');
  const filePreview = document.getElementById('filePreview');
  const fileName = document.getElementById('fileName');
  const fileSize = document.getElementById('fileSize');
  const fileType = document.getElementById('fileType');
  const removeFileBtn = document.getElementById('removeFile');
  const submitBtn = document.getElementById('submitBtn');
  const resultDiv = document.getElementById('result');
  const noteLinkDiv = document.getElementById('noteLink');
  const copyBtn = document.getElementById('copyBtn');
  const loadingDiv = document.getElementById('loading');
  
  let selectedFile = null;
  
  // Handle file selection
  attachmentInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    // Check file size (limit to 15MB)
    if (file.size > 15 * 1024 * 1024) {
      alert('File is too large. Maximum size is 15MB.');
      attachmentInput.value = '';
      return;
    }
    
    selectedFile = file;
    // Sanitize filename before display
    const sanitizedFileName = window.securityUtils.sanitizeContent(file.name);
    window.securityUtils.safeSetTextContent(fileNameDisplay, sanitizedFileName);
    
    // Display sanitized file details
    window.securityUtils.safeSetTextContent(fileName, `Name: ${sanitizedFileName}`);
    window.securityUtils.safeSetTextContent(fileSize, `Size: ${formatFileSize(file.size)}`);
    window.securityUtils.safeSetTextContent(fileType, `Type: ${window.securityUtils.sanitizeContent(file.type || 'Unknown')}`);
    
    // Show file preview
    createFilePreviewElement(file);
    
    // Show file details
    fileDetails.classList.remove('hidden');
  });
  
  // Format file size to human-readable format
  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' bytes';
    else if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    else return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }
  
  // Create file preview
  function createFilePreviewElement(file) {
    filePreview.innerHTML = '';
    
    if (file.type.startsWith('image/')) {
      // Image preview
      const reader = new FileReader();
      reader.onload = (e) => {
        const img = document.createElement('img');
        img.src = e.target.result;
        filePreview.appendChild(img);
      };
      reader.readAsDataURL(file);
    } else {
      // Generic file icon based on type
      const icon = document.createElement('div');
      icon.className = 'file-icon';
      
      if (file.type.startsWith('video/')) {
        icon.innerHTML = '🎬'; // 🎬
      } else if (file.type.startsWith('audio/')) {
        icon.innerHTML = '🎵'; // 🎵
      } else if (file.type.includes('pdf')) {
        icon.innerHTML = '📄'; // 📄
      } else if (file.type.includes('word') || file.name.endsWith('.doc') || file.name.endsWith('.docx')) {
        icon.innerHTML = '📝'; // 📝
      } else if (file.type.includes('spreadsheet') || file.name.endsWith('.xls') || file.name.endsWith('.xlsx')) {
        icon.innerHTML = '📊'; // 📊
      } else if (file.type.includes('presentation') || file.name.endsWith('.ppt') || file.name.endsWith('.pptx')) {
        icon.innerHTML = '📽️'; // 📽️
      } else if (file.type.includes('zip') || file.type.includes('compressed')) {
        icon.innerHTML = '🗜️'; // 🗜️
      } else {
        icon.innerHTML = '📎'; // 📎
      }
      
      filePreview.appendChild(icon);
    }
  }
  
  // Remove selected file
  removeFileBtn.addEventListener('click', () => {
    selectedFile = null;
    attachmentInput.value = '';
    fileNameDisplay.textContent = 'No file selected';
    fileDetails.classList.add('hidden');
  });
  
  // Make the file button trigger the hidden file input
  document.querySelector('.file-button').addEventListener('click', () => {
    attachmentInput.click();
  });

  /**
   * Handles the form submission and note creation
   */
  noteForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const message = messageInput.value.trim();
    if (!message) {
      alert('Please enter a message');
      return;
    }
    
    try {
      // Show loading state
      noteForm.style.display = 'none';
      loadingDiv.style.display = 'block';
      submitBtn.disabled = true;
      
      // Generate encryption key
      const encryptionKey = await generateEncryptionKey();
      
      // Encrypt the message using the generated key
      const encryptedMessage = await encryptMessage(message, encryptionKey);
      
      // Prepare request data
      const requestData = { encryptedMessage };
      
      // Handle file attachment if present
      if (selectedFile) {
        try {
          // Encrypt the file
          const encryptedFile = await encryptFile(selectedFile, encryptionKey);
          requestData.attachment = {
            name: encryptedFile.name,
            type: encryptedFile.type,
            data: encryptedFile.data
          };
        } catch (fileError) {
          console.error('Error encrypting file:', fileError);
          // Continue without the file if encryption fails
        }
      }
      
      // Send the encrypted data to the server
      const response = await fetch(`${API_BASE_URL}/api/note`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestData)
      });
      
      if (!response.ok) {
        throw new Error('Failed to create note');
      }
      
      const data = await response.json();
      
      // Generate the secure note URL with the encryption key in the hash
      const noteUrl = `${window.location.origin}/view.html?id=${data.id}#${encryptionKey}`;
      
      // Display the result with sanitization
      window.securityUtils.safeSetTextContent(noteLinkDiv, noteUrl);
      resultDiv.classList.remove('hidden');
      loadingDiv.style.display = 'none';
      
      // Set up copy button
      copyBtn.addEventListener('click', () => {
        // Use a sanitized URL value when copying to clipboard
        const sanitizedUrl = window.securityUtils.sanitizeContent(noteUrl);
        navigator.clipboard.writeText(sanitizedUrl)
          .then(() => {
            window.securityUtils.safeSetTextContent(copyBtn, 'Copied!');
            setTimeout(() => {
              window.securityUtils.safeSetTextContent(copyBtn, 'Copy Link');
            }, 2000);
          })
          .catch(err => {
            console.error('Failed to copy: ', err);
          });
      });
    } catch (error) {
      console.error('Error creating note:', error);
      loadingDiv.style.display = 'none';
      noteForm.style.display = 'block';
      submitBtn.disabled = false;
      showError('Failed to create secure note. Please try again.');
    }
  });
});
