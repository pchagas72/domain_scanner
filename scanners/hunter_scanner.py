import requests
from utils.helper import log_info, log_error, log_warning, log_success


def find_emails_with_hunter(domain, hunter_api_key, helper):
    """Searches for email addresses using the Hunter.io API."""
    log_info(f'\n--- Searching for emails with Hunter.io ---', helper)
    if not hunter_api_key:
        log_warning(
            '[!] Hunter.io API key not provided. Skipping email search.',
            helper,
        )
        return []

    url = f'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={hunter_api_key}'
    found_emails = []
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        emails = data.get('data', {}).get('emails', [])
        if not emails:
            log_info(
                '[-] No public email addresses found for this domain on Hunter.io.',
                helper,
            )
            return []

        log_success(f'[+] Found {len(emails)} email(s):', helper)
        for email_info in emails:
            email_address = email_info.get('value')
            if email_address:
                log_info(f'  - {email_address}', helper)
                found_emails.append(email_address)
        return found_emails
    except requests.RequestException as e:
        log_error(f'An error occurred during Hunter.io lookup: {e}', helper)
        return []
