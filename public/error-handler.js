/**
 * Enhanced Error Handling and User Feedback System
 * Provides comprehensive error display and user notifications
 */

class ErrorHandler {
  constructor() {
    this.errorDisplay = null;
    this.successNotification = null;
    this.validationErrors = null;
    this.init();
  }

  init() {
    // Wait for DOM if not ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.setupElements());
    } else {
      this.setupElements();
    }
  }

  setupElements() {
    // Get DOM elements
    this.errorDisplay = document.getElementById('errorDisplay');
    this.successNotification = document.getElementById('successNotification');
    this.validationErrors = document.getElementById('validationErrors');
    
    
    // Bind event listeners
    this.bindEventListeners();
  }

  bindEventListeners() {
    // Retry button
    const retryBtn = document.getElementById('retryBtn');
    if (retryBtn) {
      retryBtn.addEventListener('click', () => {
        this.hideError();
        // Trigger form resubmission if available
        const form = document.getElementById('noteForm');
        if (form) {
          const submitBtn = document.getElementById('submitBtn');
          if (submitBtn && !submitBtn.disabled) {
            submitBtn.click();
          }
        }
      });
    }

    // Dismiss error button
    const dismissBtn = document.getElementById('dismissErrorBtn');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => {
        this.hideError();
      });
    }

    // Auto-hide success notifications
    if (this.successNotification) {
      this.successNotification.addEventListener('click', () => {
        this.hideSuccess();
      });
    }
  }

  // Show different types of errors
  showError(title, message, type = 'error') {
    if (!this.errorDisplay) {
      // Fallback to alert
      alert(`${title}: ${message}`);
      return;
    }

    const errorTitle = document.getElementById('errorTitle');
    const errorMessage = document.getElementById('errorMessage');
    const errorIcon = this.errorDisplay.querySelector('.error-icon');

    if (errorTitle) errorTitle.textContent = title;
    if (errorMessage) errorMessage.textContent = message;
    
    // Update icon based on error type
    if (errorIcon) {
      switch (type) {
        case 'network':
          errorIcon.textContent = '🌐';
          break;
        case 'validation':
          errorIcon.textContent = '📝';
          break;
        case 'security':
          errorIcon.textContent = '🔒';
          break;
        case 'file':
          errorIcon.textContent = '📁';
          break;
        default:
          errorIcon.textContent = '⚠️';
      }
    }

    this.errorDisplay.classList.remove('hidden');
    this.hideSuccess();
    this.hideValidationErrors();
    
    // Scroll to error
    this.errorDisplay.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  // Show network-specific errors
  showNetworkError(statusCode, responseText) {
    let title = 'Network Error';
    let message = 'Unable to connect to the server. Please check your internet connection and try again.';

    switch (statusCode) {
      case 400:
        title = 'Invalid Request';
        message = responseText || 'The request contains invalid data. Please check your input and try again.';
        break;
      case 413:
        title = 'File Too Large';
        message = 'The attached file is too large. Please select a file smaller than 15MB.';
        break;
      case 429:
        title = 'Too Many Requests';
        message = 'You are sending requests too quickly. Please wait a moment and try again.';
        break;
      case 500:
        title = 'Server Error';
        message = 'An internal server error occurred. Please try again later.';
        break;
      case 0:
        title = 'Connection Failed';
        message = 'Unable to reach the server. Please check your internet connection.';
        break;
    }

    this.showError(title, message, 'network');
  }

  // Show validation errors
  showValidationErrors(errors) {
    if (!this.validationErrors || !Array.isArray(errors) || errors.length === 0) return;

    const validationList = document.getElementById('validationList');
    if (!validationList) return;

    // Clear previous errors
    validationList.innerHTML = '';

    // Add each error
    errors.forEach(error => {
      const li = document.createElement('li');
      li.textContent = error;
      validationList.appendChild(li);
    });

    this.validationErrors.classList.remove('hidden');
    this.hideError();
    this.hideSuccess();

    // Scroll to validation errors
    this.validationErrors.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  // Show field-specific validation errors
  showFieldError(fieldId, message) {
    const field = document.getElementById(fieldId);
    if (!field) return;

    const formGroup = field.closest('.form-group');
    if (!formGroup) return;

    // Add error class
    formGroup.classList.add('error');

    // Remove existing error message
    const existingError = formGroup.querySelector('.field-error');
    if (existingError) {
      existingError.remove();
    }

    // Add new error message
    const errorSpan = document.createElement('span');
    errorSpan.className = 'field-error';
    errorSpan.textContent = message;
    field.parentNode.appendChild(errorSpan);

    // Remove error on input change
    const removeError = () => {
      formGroup.classList.remove('error');
      if (errorSpan.parentNode) {
        errorSpan.remove();
      }
      field.removeEventListener('input', removeError);
      field.removeEventListener('change', removeError);
    };

    field.addEventListener('input', removeError);
    field.addEventListener('change', removeError);
  }

  // Show success message
  showSuccess(message = 'Operation completed successfully!') {
    if (!this.successNotification) return;

    const successMessage = document.getElementById('successMessage');
    if (successMessage) {
      successMessage.textContent = message;
    }

    this.successNotification.classList.remove('hidden');
    this.hideError();
    this.hideValidationErrors();

    // Auto-hide after 3 seconds
    setTimeout(() => {
      this.hideSuccess();
    }, 3000);
  }

  // Hide error display
  hideError() {
    if (this.errorDisplay) {
      this.errorDisplay.classList.add('hidden');
    }
  }

  // Hide success notification
  hideSuccess() {
    if (this.successNotification) {
      this.successNotification.classList.add('hidden');
    }
  }

  // Hide validation errors
  hideValidationErrors() {
    if (this.validationErrors) {
      this.validationErrors.classList.add('hidden');
    }
    
    // Remove field-specific errors
    document.querySelectorAll('.form-group.error').forEach(group => {
      group.classList.remove('error');
      const errorMsg = group.querySelector('.field-error');
      if (errorMsg) errorMsg.remove();
    });
  }

  // Show toast notification
  showToast(message, type = 'info', duration = 4000) {
    const toast = document.createElement('div');
    toast.className = `toast ${type} hidden`;
    toast.textContent = message;

    document.body.appendChild(toast);

    // Show toast with CSS transition
    setTimeout(() => {
      toast.classList.remove('hidden');
    }, 10);

    // Auto-remove toast
    setTimeout(() => {
      if (toast.parentNode) {
        toast.classList.add('hidden');
        setTimeout(() => {
          if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
          }
        }, 200);
      }
    }, duration);

    // Click to dismiss
    toast.addEventListener('click', () => {
      if (toast.parentNode) {
        toast.classList.add('hidden');
        setTimeout(() => {
          if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
          }
        }, 200);
      }
    });
  }

  // Clear all notifications
  clearAll() {
    this.hideError();
    this.hideSuccess();
    this.hideValidationErrors();
    
    // Remove all toasts
    document.querySelectorAll('.toast').forEach(toast => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    });
  }

  // Handle fetch errors
  handleFetchError(error, response = null) {
    console.error('Fetch error:', error);

    if (response) {
      // Handle HTTP errors
      response.text().then(text => {
        try {
          const data = JSON.parse(text);
          this.showNetworkError(response.status, data.error || data.message);
        } catch (e) {
          this.showNetworkError(response.status, text);
        }
      }).catch(() => {
        this.showNetworkError(response.status);
      });
    } else {
      // Handle network errors
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        this.showError('Connection Error', 'Unable to connect to the server. Please check your internet connection and try again.', 'network');
      } else {
        this.showError('Unexpected Error', error.message || 'An unexpected error occurred. Please try again.', 'error');
      }
    }
  }

  // Validate form before submission
  validateForm(formData) {
    const errors = [];

    // Check message content
    const message = formData.get('message');
    if (!message || message.trim().length === 0) {
      errors.push('Message content is required');
      this.showFieldError('message', 'Please enter a message');
    } else if (message.length > 50000) {
      errors.push('Message is too long (maximum 50,000 characters)');
      this.showFieldError('message', 'Message is too long');
    }

    // Check file attachment if present
    const fileInput = document.getElementById('attachment');
    if (fileInput && fileInput.files.length > 0) {
      const file = fileInput.files[0];
      
      if (file.size > 15 * 1024 * 1024) { // 15MB
        errors.push('Attached file is too large (maximum 15MB)');
        this.showFieldError('attachment', 'File is too large');
      }

      // Check for suspicious file extensions
      const suspiciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com'];
      const fileName = file.name.toLowerCase();
      if (suspiciousExtensions.some(ext => fileName.endsWith(ext))) {
        errors.push('File type not allowed for security reasons');
        this.showFieldError('attachment', 'File type not allowed');
      }
    }

    if (errors.length > 0) {
      this.showValidationErrors(errors);
      return false;
    }

    return true;
  }
}

// Initialize error handler when DOM is ready
let errorHandler;

function initializeErrorHandler() {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      errorHandler = new ErrorHandler();
      window.errorHandler = errorHandler;
    });
  } else {
    errorHandler = new ErrorHandler();
    window.errorHandler = errorHandler;
  }
}

// Initialize immediately
initializeErrorHandler();

// Export for use in other scripts
window.ErrorHandler = ErrorHandler;
