import socket
import requests
import whoisdomain as whois
from utils.helper import log_info, log_error, log_warning, log_success


def get_whois_and_ip_info(domain, ipinfo_api_key, helper):
    """
    Performs a WHOIS lookup and gets geolocation information for the name servers.
    """
    log_info(f'\n--- Performing WHOIS and IP Lookup for {domain} ---', helper)
    try:
        query = whois.query(domain)
        if not query:
            log_error(
                f'WHOIS query failed for {domain}. The domain may not be registered.',
                helper,
            )
            return

        log_info(f'\n\n**WHOIS Information:**', helper)
        try:
            owner = (
                ', '.join(query.owner)
                if isinstance(query.owner, list)
                else query.owner or 'N/A'
            )
            log_info(f'  Owner: {owner}', helper)
        except Exception:
            pass
        log_info(f'  Registrar: {query.registrar}', helper)
        log_info(f'  Creation Date: {query.creation_date}', helper)
        log_info(f'  Last Updated: {query.last_updated}', helper)
        log_info(f'  Expiration Date: {query.expiration_date}', helper)
        log_info(f"  Name Servers: {', '.join(query.name_servers)}", helper)
        emails = ', '.join(query.emails) if query.emails else 'N/A'
        log_info(f'  Associated Emails: {emails}', helper)

        if not ipinfo_api_key:
            log_warning(
                '\n[!] IPinfo API key not provided. Skipping geolocation.',
                helper,
            )
            return

        log_info(f'\n**IPINFO scan results:**', helper)
        for server in query.name_servers:
            try:
                ip_addr = socket.gethostbyname(server)
                url = (
                    f'https://ipinfo.io/{ip_addr}/json?token={ipinfo_api_key}'
                )
                response = requests.get(url, timeout=5)
                response.raise_for_status()
                data = response.json()
                log_success(
                    f"  Geolocation - {server} ({ip_addr}): {data.get('city', 'N/A')}, {data.get('region', 'N/A')} {data.get('country', 'N/A')}",
                    helper,
                )
                log_info(
                    f"  Geolocation - {server} ({ip_addr}): (Lat/Lon) {data.get('loc')}",
                    helper,
                )
                log_info(
                    f"  ISP - {server} ({ip_addr}): {data.get('org')}", helper
                )
                log_info(
                    f"  Postal - {server} ({ip_addr}): {data.get('postal')}",
                    helper,
                )
                log_info('\n', helper)
            except socket.gaierror:
                log_error(f'  - Could not resolve IP for {server}', helper)
            except requests.RequestException as e:
                log_error(
                    f'  - Could not get location for {server}: {e}', helper
                )
    except Exception as e:
        log_error(f'An error occurred during WHOIS lookup: {e}', helper)
