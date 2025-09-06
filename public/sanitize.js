/**
 * Client-side sanitization utilities for protecting against XSS
 * This small utility adds an extra layer of protection beyond server-side sanitization
 * Uses browser-compatible sanitization without external dependencies
 */

// Browser-compatible DOMPurify alternative for basic sanitization
const createSanitizer = () => {
  return {
    sanitize: (content) => {
      if (typeof content !== 'string') return '';
      
      // Comprehensive HTML and script sanitization
      return content
        // Remove script tags and their content
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        // Remove all HTML tags
        .replace(/<[^>]*>/g, '')
        // Remove javascript: and data: protocols
        .replace(/javascript:/gi, '')
        .replace(/data:/gi, '')
        .replace(/vbscript:/gi, '')
        // Remove event handlers
        .replace(/on\w+\s*=/gi, '')
        // Escape remaining dangerous characters
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    }
  };
};

/**
 * Sanitizes content for safe display in the browser
 * @param {string} content - Content to sanitize
 * @returns {string} - Sanitized content
 */
function sanitizeContent(content) {
  if (typeof content !== 'string') return '';
  
  // Use the enhanced sanitizer
  const sanitizer = createSanitizer();
  return sanitizer.sanitize(content);
}

/**
 * Safely sets text content to an element
 * @param {HTMLElement} element - Element to set content for
 * @param {string} content - Content to set
 */
function safeSetTextContent(element, content) {
  if (!element) return;
  
  // Use textContent which doesn't parse HTML
  element.textContent = sanitizeContent(content);
}

/**
 * Safely renders text in the UI avoiding XSS
 * @param {string} selector - CSS selector for the target element
 * @param {string} content - Content to render
 */
function safeRender(selector, content) {
  const element = document.querySelector(selector);
  if (!element) return;
  
  safeSetTextContent(element, content);
}

// Expose the sanitization utilities
window.securityUtils = {
  sanitizeContent,
  safeSetTextContent,
  safeRender
};
