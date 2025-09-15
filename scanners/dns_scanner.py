import dns.resolver
from utils.helper import log_info, log_error, log_success

RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']

def get_dns_records(domain, helper):
    """Queries for various DNS records and returns them as a dictionary."""
    is_worker = helper is None
    if not is_worker:
        log_info(f'\n--- Querying DNS Records for {domain} ---', helper)

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    dns_results = {}
    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            dns_results[record_type] = [rdata.to_text() for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dns_results[record_type] = []
        except Exception:
            dns_results[record_type] = ["Error querying record"]

    if not is_worker:
        for record_type, records in dns_results.items():
            if records:
                log_success(f'[+] Found {record_type} records:', helper)
                for record in records:
                    log_info(f'  - {record}', helper)
            else:
                log_info(f'[-] No {record_type} records found.', helper)

    return dns_results
