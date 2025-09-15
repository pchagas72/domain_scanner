import requests
from utils.helper import log_info, log_error, log_warning, log_success

def find_emails_with_hunter(domain, hunter_api_key, helper):
    """Searches for email addresses and returns them in a dictionary."""
    is_worker = helper is None
    if not is_worker:
        log_info(f'\n--- Searching for emails with Hunter.io ---', helper)

    if not hunter_api_key:
        if not is_worker:
            log_warning('[!] Hunter.io API key not provided. Skipping.', helper)
        return {'emails': []}

    url = f'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={hunter_api_key}'
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        emails = [e.get('value') for e in data.get('data', {}).get('emails', []) if e.get('value')]
        
        if not is_worker:
            if emails:
                log_success(f'[+] Found {len(emails)} email(s):', helper)
                for email in emails:
                    log_info(f'  - {email}', helper)
            else:
                log_info('[-] No public emails found on Hunter.io.', helper)
        
        return {'emails': emails}
    except requests.RequestException as e:
        if not is_worker:
            log_error(f'An error occurred during Hunter.io lookup: {e}', helper)
        return {'emails': [], 'error': str(e)}
