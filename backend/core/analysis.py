import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Dict, Any
import logging

# Import modul checkdmarc utama (TANPA import exception spesifik)
import checkdmarc

from core.dns_resolver import create_resilient_resolver

logger = logging.getLogger(__name__)

# Thread pool untuk menjalankan operasi blocking (DNS queries)
executor = ThreadPoolExecutor(max_workers=5)

async def async_check_spf(domain: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Menjalankan check_spf secara async menggunakan thread pool."""
    if not domain:
        return {"status": "n/a", "reason": "No domain provided"}
    
    loop = asyncio.get_event_loop()
    resolver = create_resilient_resolver(timeout)
    
    def run_spf_check(d):
        try:
            # checkdmarc.check_spf() adalah fungsi utama untuk validasi SPF
            result = checkdmarc.check_spf(d, resolver=resolver)
            return result
        except Exception as e:
            # Tangkap semua exception secara generik
            return {"error": str(e), "valid": False}

    func = partial(run_spf_check, domain)
    
    try:
        result = await loop.run_in_executor(executor, func)
        return result
    except Exception as e:
        logger.error(f"Error checking SPF for {domain}: {e}")
        return {"error": str(e), "valid": False}

async def async_check_dmarc(domain: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Menjalankan check_dmarc secara async menggunakan thread pool."""
    if not domain:
        return {"status": "n/a", "reason": "No domain provided"}
    
    loop = asyncio.get_event_loop()
    resolver = create_resilient_resolver(timeout)
    
    def run_dmarc_check(d):
        try:
            # checkdmarc.check_dmarc() adalah fungsi utama untuk validasi DMARC
            result = checkdmarc.check_dmarc(d, resolver=resolver)
            return result
        except Exception as e:
            # Tangkap semua exception secara generik
            return {"error": str(e), "valid": False}

    func = partial(run_dmarc_check, domain)
    
    try:
        result = await loop.run_in_executor(executor, func)
        return result
    except Exception as e:
        logger.error(f"Error checking DMARC for {domain}: {e}")
        return {"error": str(e), "valid": False}

async def analyze_authenticity(from_domain: str) -> Dict[str, Any]:
    """
    Analisis lengkap SPF dan DMARC untuk domain pengirim.
    """
    if not from_domain:
        return {
            "spf": {"status": "n/a", "reason": "No from domain"},
            "dkim": {"status": "n/a", "reason": "No from domain"},
            "dmarc": {"status": "n/a", "reason": "No from domain"},
        }
    
    # Jalankan check SPF dan DMARC secara paralel
    spf_result, dmarc_result = await asyncio.gather(
        async_check_spf(from_domain, timeout=5.0),
        async_check_dmarc(from_domain, timeout=5.0),
        return_exceptions=True
    )
    
    results = {}
    
    # --- Proses Hasil SPF ---
    if isinstance(spf_result, Exception):
        results["spf"] = {"status": "error", "reason": str(spf_result)}
    elif "error" in spf_result:
        results["spf"] = {"status": "fail", "reason": spf_result["error"]}
    else:
        # check_spf mengembalikan dict dengan kunci 'valid' (boolean)
        is_valid = spf_result.get("valid", False)
        results["spf"] = {
            "status": "pass" if is_valid else "fail",
            "record": spf_result.get("record", ""),
        }
    
    # --- Proses Hasil DMARC ---
    if isinstance(dmarc_result, Exception):
        results["dmarc"] = {"status": "error", "reason": str(dmarc_result)}
    elif "error" in dmarc_result:
        results["dmarc"] = {"status": "fail", "reason": dmarc_result["error"]}
    else:
        # check_dmarc mengembalikan dict dengan struktur kompleks
        is_valid = dmarc_result.get("valid", False)
        dmarc_record = dmarc_result.get("dmarc_record", {})
        policy = dmarc_record.get("p", "none") if isinstance(dmarc_record, dict) else "none"
        results["dmarc"] = {
            "status": "pass" if is_valid else "fail",
            "policy": policy,
            "record": dmarc_result.get("record", ""),
        }
    
    # --- DKIM (Sederhana) ---
    # Validasi DKIM signature yang sebenarnya memerlukan parsing header 'DKIM-Signature'
    results["dkim"] = {
        "status": "not_checked", 
        "note": "DKIM signature verification requires full header analysis and public key retrieval."
    }
    
    return results