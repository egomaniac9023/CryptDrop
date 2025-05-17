/**
 * Client-side sanitization utilities for protecting against XSS
 * This small utility adds an extra layer of protection beyond server-side sanitization
 */

// Create a DOMPurify instance for sanitizing content
const createDOMPurify = () => {
  // Check if we're in a browser environment
  if (typeof window !== 'undefined') {
    // Create a document object for DOMPurify to use
    const { JSDOM } = require('jsdom');
    const window = new JSDOM('').window;
    const DOMPurify = require('dompurify')(window);
    
    // Configure DOMPurify for maximum safety
    DOMPurify.setConfig({
      ALLOWED_TAGS: [],         // No HTML tags allowed at all
      ALLOWED_ATTR: [],         // No attributes allowed
      ALLOW_DATA_ATTR: false,   // Disallow data attributes
      USE_PROFILES: { html: false }, // Don't use HTML profiles
      FORBID_TAGS: ['style', 'script', 'iframe', 'frame', 'object', 'embed', 'form'],
      FORBID_ATTR: ['style', 'onerror', 'onload', 'onclick', 'onmouseover']
    });
    
    return DOMPurify;
  }
  
  // Fallback for non-browser environments
  return {
    sanitize: (content) => {
      if (typeof content !== 'string') return '';
      
      // Simple HTML tag stripping for non-browser environments
      return content
        .replace(/<[^>]*>/g, '') // Remove HTML tags
        .replace(/&lt;/g, '<')    // Fix common entities
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&')
        .replace(/&quot;/g, '"')
        .replace(/&#x27;/g, "'")
        .replace(/&#x2F;/g, '/');
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
  
  // Basic sanitization for all environments
  const sanitized = content
    // Remove potentially dangerous characters and patterns
    .replace(/javascript:/gi, '')
    .replace(/data:/gi, '')
    .replace(/vbscript:/gi, '')
    .replace(/on\w+=/gi, '')
    .replace(/<script.*?>.*?<\/script>/gis, '')
    .replace(/<iframe.*?>.*?<\/iframe>/gis, '')
    .replace(/<frame.*?>.*?<\/frame>/gis, '')
    .replace(/<object.*?>.*?<\/object>/gis, '')
    .replace(/<embed.*?>.*?<\/embed>/gis, '')
    .replace(/<form.*?>.*?<\/form>/gis, '')
    // Escape angle brackets to prevent HTML injection
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
    
  // Return the sanitized content
  return sanitized;
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
