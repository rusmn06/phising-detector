import bleach
from typing import Optional

# ⭐ JANGAN ADA IMPORT DARI utils.sanitizer DI SINI! ⭐

# Daftar tag HTML yang DIIZINKAN (whitelist approach)
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
    Sanitasi konten HTML dari email untuk mencegah XSS.
    """
    if not html_content:
        return None
    
    # Batasi panjang konten untuk mencegah DoS
    if len(html_content) > max_length:
        html_content = html_content[:max_length] + "... [konten dipotong]"
    
    # Bersihkan HTML menggunakan bleach
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
    Validasi dan sanitasi URL untuk mencegah javascript: dan scheme berbahaya.
    """
    if not url:
        return None
    
    # Cek scheme berbahaya
    dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:']
    url_lower = url.lower().strip()
    
    for scheme in dangerous_schemes:
        if url_lower.startswith(scheme):
            return None
    
    return url