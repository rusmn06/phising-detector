import mailparser
import logging
import re
from typing import Dict, Optional, List
from utils.sanitizer import sanitize_html, sanitize_url

logger = logging.getLogger(__name__)

def parse_eml_file(file_content: bytes) -> Dict[str, Optional[str]]:
    """
    Parse file .eml dan ekstrak konten penting.
    """
    try:
        # Parse email dari bytes
        email_message = mailparser.parse_from_bytes(file_content)
        
        # ⭐ DEBUG: Print semua attribute yang tersedia ⭐
        logger.info(f"=== EMAIL PARSER DEBUG ===")
        logger.info(f"Available attributes: {[attr for attr in dir(email_message) if not attr.startswith('_')]}")
        
        # ⭐ EKSTRAK BODY (mailparser return LIST, bukan string!) ⭐
        # Coba beberapa variasi nama atribut
        text_parts = getattr(email_message, 'text_plain', None) or getattr(email_message, 'body_text', None) or []
        html_parts = getattr(email_message, 'text_html', None) or getattr(email_message, 'body_html', None) or []
        
        logger.info(f"text_parts type: {type(text_parts)}, value: {text_parts}")
        logger.info(f"html_parts type: {type(html_parts)}, value: {html_parts}")
        
        # Gabungkan semua parts menjadi string
        text_content = "".join(text_parts) if isinstance(text_parts, list) else str(text_parts or "")
        html_content = "".join(html_parts) if isinstance(html_parts, list) else str(html_parts or "")
        
        logger.info(f"text_content length: {len(text_content)}")
        logger.info(f"html_content length: {len(html_content)}")
        
        # ⭐ SANITASI HTML SEBELUM RETURN ⭐
        sanitized_html = sanitize_html(html_content)
        logger.info(f"sanitized_html length: {len(sanitized_html) if sanitized_html else 0}")
        
        # ⭐ EKSTRAK HEADER PENGIRIM ⭐
        from_list = getattr(email_message, 'from_', None) or []
        from_header = ""
        if isinstance(from_list, list) and len(from_list) > 0:
            first_sender = from_list[0]
            if isinstance(first_sender, dict):
                from_header = first_sender.get("address", "")
            else:
                from_header = str(first_sender)
        
        from_domain = extract_domain_from_email(from_header)
        subject = getattr(email_message, 'subject', "") or ""
        
        logger.info(f"from_domain: {from_domain}, subject: {subject}")
        logger.info(f"=== END DEBUG ===")
        
        # ⭐ EKSTRAK URL ⭐
        urls = extract_urls_from_content(text_content + " " + html_content)
        safe_urls = [url for url in urls if sanitize_url(url)]
        
        return {
            "text": text_content,
            "html": html_content,
            "sanitized_html": sanitized_html,
            "headers": "",
            "from_domain": from_domain,
            "urls": safe_urls,
            "subject": subject,
            "from": from_header,
            "to": "",
        }
        
    except Exception as e:
        logger.error(f"Error parsing .eml file: {e}")
        return {
            "text": "",
            "html": "",
            "sanitized_html": "",
            "headers": "",
            "from_domain": "",
            "urls": [],
            "subject": "",
            "from": "",
            "to": "",
        }

def extract_domain_from_email(email_header: str) -> str:
    if not email_header:
        return ""
    match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', str(email_header))
    if match:
        return match.group(1).lower()
    return ""

def extract_urls_from_content(content: str) -> List[str]:
    if not content:
        return []
    url_pattern = r'https?://[^\s<>"\'\{\}\|\\\^\`\[\]]+'
    urls = re.findall(url_pattern, str(content))
    return list(set(urls))