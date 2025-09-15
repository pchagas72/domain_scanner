import socket
import requests
import whoisdomain as whois
from utils.helper import log_info, log_error, log_warning, log_success

def get_whois_and_ip_info(domain, ipinfo_api_key, helper):
    """Performs WHOIS/IP lookup and returns results as a dictionary."""
    is_worker = helper is None
    if not is_worker:
        log_info(f'\n--- Performing WHOIS and IP Lookup for {domain} ---', helper)

    results = {}
    try:
        query = whois.query(domain)
        if not query:
            if not is_worker: log_error(f'WHOIS query failed for {domain}.', helper)
            return {'error': 'WHOIS query failed.'}

        results['whois'] = {
            'owner': query.owner,
            'registrar': query.registrar,
            'creation_date': str(query.creation_date),
            'last_updated': str(query.last_updated),
            'expiration_date': str(query.expiration_date),
            'name_servers': query.name_servers,
            'emails': query.emails
        }

        if not is_worker:
            log_info(f'\n\n**WHOIS Information:**', helper)
            for key, value in results['whois'].items():
                log_info(f"  {key.replace('_', ' ').title()}: {value}", helper)

        if ipinfo_api_key and query.name_servers:
            results['ipinfo'] = []
            if not is_worker: log_info(f'\n**IPINFO scan results:**', helper)
            for server in query.name_servers:
                try:
                    ip_addr = socket.gethostbyname(server)
                    url = f'https://ipinfo.io/{ip_addr}/json?token={ipinfo_api_key}'
                    response = requests.get(url, timeout=5)
                    response.raise_for_status()
                    data = response.json()
                    results['ipinfo'].append(data)
                    if not is_worker:
                        log_success(f"  Geolocation - {server} ({ip_addr}): {data.get('city')}, {data.get('country')}", helper)
                except (socket.gaierror, requests.RequestException):
                    pass
        return results
    except Exception as e:
        if not is_worker: log_error(f'An error occurred during WHOIS lookup: {e}', helper)
        return {'error': str(e)}
