import socket
import ssl
import datetime
from utils.helper import log_info, log_error, log_warning, log_success


def get_ssl_certificate_info(hostname, port=443, helper=None):
    """
    Connects to a server to get its SSL certificate details.
    """
    log_info(f'\n--- Scanning SSL Certificate for {hostname} ---', helper)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                not_before_str = cert.get('notBefore')
                not_after_str = cert.get('notAfter')

                log_info(f'\n**SSL Certificate Details:**', helper)
                log_info(
                    f"  Subject: {subject.get('commonName', 'N/A')}", helper
                )
                log_info(
                    f"  Issuer: {issuer.get('commonName', 'N/A')}", helper
                )

                if not_before_str and not_after_str:
                    not_before = datetime.datetime.strptime(
                        not_before_str, '%b %d %H:%M:%S %Y %Z'
                    )
                    not_after = datetime.datetime.strptime(
                        not_after_str, '%b %d %H:%M:%S %Y %Z'
                    )
                    now_utc = datetime.datetime.now(datetime.timezone.utc)
                    not_after_utc = not_after.replace(
                        tzinfo=datetime.timezone.utc
                    )
                    days_left = (not_after_utc - now_utc).days

                    log_info(f'  Valid From: {not_before}', helper)
                    log_info(f'  Valid Until: {not_after}', helper)

                    if days_left < 0:
                        log_error(
                            f'  Status: EXPIRED {-days_left} days ago', helper
                        )
                    elif days_left < 30:
                        log_warning(
                            f'  Status: Expires in {days_left} days', helper
                        )
                    else:
                        log_success(
                            f'  Status: Valid ({days_left} days remaining)',
                            helper,
                        )
    except (socket.timeout, ConnectionRefusedError):
        log_error(
            f'Connection timed out or was refused for {hostname}:{port}',
            helper,
        )
    except ssl.SSLError as e:
        log_error(
            f'SSL error for {hostname}: {e}. The domain may not support HTTPS or have a misconfiguration.',
            helper,
        )
    except Exception as e:
        log_error(
            f'An error occurred during SSL scan for {hostname}: {e}', helper
        )
