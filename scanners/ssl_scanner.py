import socket
import ssl
import datetime
from utils.helper import log_info, log_error, log_success, resolve_domain

def get_ssl_certificate_info(hostname, port=443, helper=None):
    """Gets SSL certificate details and returns them as a dictionary."""
    is_worker = helper is None
    if not is_worker:
        log_info(f'\n--- Scanning SSL Certificate for {hostname} ---', helper)
    
    _, resolved_name = resolve_domain(hostname, helper or type('d', (), {'log': lambda *a: None})())
    if not resolved_name:
        error_msg = f'Could not resolve hostname {hostname}'
        if not is_worker: log_error(error_msg, helper)
        return {'error': error_msg}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((resolved_name, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=resolved_name) as ssock:
                cert = ssock.getpeercert()
                
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                cert_data = {
                    'subject': subject.get('commonName', 'N/A'),
                    'issuer': issuer.get('commonName', 'N/A'),
                    'valid_from': cert.get('notBefore'),
                    'valid_until': cert.get('notAfter')
                }

                if not is_worker:
                    log_info(f'\n**SSL Certificate Details:**', helper)
                    log_info(f"  Subject: {cert_data['subject']}", helper)
                    log_info(f"  Issuer: {cert_data['issuer']}", helper)
                    log_info(f"  Valid From: {cert_data['valid_from']}", helper)
                    log_info(f"  Valid Until: {cert_data['valid_until']}", helper)

                return cert_data
    except Exception as e:
        error_msg = f'SSL scan error for {resolved_name}: {e}'
        if not is_worker: log_error(error_msg, helper)
        return {'error': error_msg}
