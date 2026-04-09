"""
HTML sanitization utility to prevent XSS attacks.
Uses bleach library for safe HTML cleaning.
"""
import bleach
from typing import Optional

# Allowed HTML tags (whitelist approach)
ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li',
    'table', 'tr', 'th', 'td', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'blockquote', 'pre', 'code', 'hr', 'div', 'span', 'html', 'body'
]

ALLOWED_ATTRIBUTES = {
    '*': ['title', 'style'],
    'a': ['href', 'title', 'target'],
    'img': ['src', 'alt', 'title'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
}

ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']


def sanitize_html(html_content: Optional[str], max_length: int = 5000) -> Optional[str]:
    """
    Sanitize HTML content from emails to prevent XSS.
    
    Args:
        html_content: Raw HTML content
        max_length: Maximum length to prevent DoS
        
    Returns:
        Sanitized HTML string or None
    """
    if not html_content:
        return None
    
    # Limit content length to prevent DoS
    if len(html_content) > max_length:
        html_content = html_content[:max_length] + "... [content truncated]"
    
    # Clean HTML using bleach
    clean_html = bleach.clean(
        text=html_content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True
    )
    
    return clean_html


def sanitize_url(url: str) -> Optional[str]:
    """
    Validate and sanitize URL to prevent javascript: and dangerous schemes.
    
    Args:
        url: URL string to validate
        
    Returns:
        Sanitized URL or None if dangerous
    """
    if not url:
        return None
    
    # Check for dangerous schemes
    dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:']
    url_lower = url.lower().strip()
    
    for scheme in dangerous_schemes:
        if url_lower.startswith(scheme):
            return None
    
    return url