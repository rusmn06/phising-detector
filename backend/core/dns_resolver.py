import dns.resolver
from typing import Optional

def create_resilient_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    """
    Membuat DNS resolver dengan timeout yang dikonfigurasi.
    Mencegah aplikasi hang saat nameserver tidak merespons.
    
    Args:
        timeout: Waktu maksimal menunggu respons DNS (detik)
        
    Returns:
        dns.resolver.Resolver yang sudah dikonfigurasi
    """
    resolver = dns.resolver.Resolver()
    
    # Timeout untuk setiap query individual
    resolver.timeout = timeout
    
    # Lifetime total untuk semua retry
    resolver.lifetime = timeout * 2
    
    # Optional: Set nameserver spesifik (misal Google DNS)
    # resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    
    return resolver