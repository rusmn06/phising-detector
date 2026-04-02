import re
from typing import List
from urllib.parse import urlparse

def extract_urls_from_content(text_content: str, html_content: str) -> List[str]:
    """
    Ekstrak semua URL dari konten email (teks + HTML).
    
    Args:
        text_content: Body teks plain dari email
        html_content: Body HTML dari email
        
    Returns:
        List URL unik yang ditemukan
    """
    # Gabungkan konten teks dan HTML untuk scanning
    combined_content = f"{text_content} {html_content}"
    
    # Pattern regex untuk menemukan URL http/https
    # Pattern ini cukup komprehensif untuk kebanyakan kasus
    url_pattern = r'https?://[^\s<>"\'\{\}\|\\\^\`\[\]]+'
    
    # Find all matches
    urls = re.findall(url_pattern, combined_content)
    
    # Bersihkan URL (hapus karakter trailing yang tidak diinginkan)
    cleaned_urls = []
    for url in urls:
        # Hapus karakter trailing yang umum tidak diinginkan
        url = url.rstrip('.,;:!?)]}\'"')
        
        # Validasi URL sederhana
        if is_valid_url(url):
            cleaned_urls.append(url)
    
    # Deduplikasi (hapus URL duplikat)
    unique_urls = list(set(cleaned_urls))
    
    return unique_urls

def is_valid_url(url: str) -> bool:
    """
    Validasi URL sederhana menggunakan urlparse.
    """
    try:
        result = urlparse(url)
        # URL valid harus punya scheme (http/https) dan netloc (domain)
        return all([result.scheme, result.netloc])
    except Exception:
        return False