"""
A all in 1 domain scanner tool, check the documentation for how-to-use
"""

import argparse
import os
from utils.helper import Helper
from scanners.whois_scanner import get_whois_and_ip_info
from scanners.ssl_scanner import get_ssl_certificate_info
from scanners.subdomain_scanner import run_subdomain_scan
from scanners.hunter_scanner import find_emails_with_hunter


def main():
    """Parses arguments and runs the selected scans."""
    parser = argparse.ArgumentParser(
        description='All-in-one domain analysis tool.'
    )
    parser.add_argument('domain', help='The target domain to analyze.')
    parser.add_argument(
        '--whois', action='store_true', help='Perform WHOIS and IP lookup.'
    )
    parser.add_argument(
        '--hunter', action='store_true', help='Perform HUNTER email lookup.'
    )
    parser.add_argument(
        '--ssl', action='store_true', help='Perform SSL certificate scan.'
    )
    parser.add_argument(
        '--subdomains', action='store_true', help='Perform a subdomain scan.'
    )
    parser.add_argument(
        '-w', '--wordlist', help='Wordlist file for subdomain scan.'
    )
    parser.add_argument(
        '-t',
        '--threads',
        type=int,
        help='Number of threads for subdomain scan.',
    )
    parser.add_argument(
        '--ipinfo-key', help='API key for ipinfo.io for better output.'
    )
    parser.add_argument(
        '--hunter-key', help='API key for hunter.io for email searching.'
    )
    parser.add_argument('--config', help='Path to a .env configuration file.')
    parser.add_argument(
        '--output', help='Path to save the output to a text file.'
    )
    args = parser.parse_args()

    helper = Helper()

    if args.output:
        helper.output_path = args.output
        try:
            with open(helper.output_path, 'w', encoding='utf-8') as f:
                pass
        except IOError as e:
            print(
                f'{helper.color_red}[-] Critical Error: Could not open output file for writing: {e}{helper.color_reset_colors}'
            )
            return

    if args.config:
        helper.read_config_env(args.config)

    ipinfo_key = args.ipinfo_key or helper.config.get('IPINFO_API_KEY')
    hunter_key = args.hunter_key or helper.config.get('HUNTER_API_KEY')
    wordlist = (
        args.wordlist or helper.config.get('WORDLIST_PATH') or 'subdomains.txt'
    )
    threads = args.threads or int(helper.config.get('THREADS', 50))

    run_all = not (args.whois or args.ssl or args.subdomains or args.hunter)

    helper.log(
        f'\nStarting analysis for: {args.domain}',
        helper.color_yellow + helper.color_bold,
    )
    if helper.output_path:
        helper.log(
            f'[*] Saving output to: {helper.output_path}', helper.color_yellow
        )

    if args.whois or run_all:
        get_whois_and_ip_info(args.domain, ipinfo_key, helper)
    if args.ssl or run_all:
        get_ssl_certificate_info(args.domain, helper=helper)
    if args.hunter or run_all:
        find_emails_with_hunter(args.domain, hunter_key, helper)
    if args.subdomains or run_all:
        if not os.path.exists(wordlist):
            helper.log(
                f"[-] Subdomain scan requires a wordlist. Default '{wordlist}' not found. Skipping scan.",
                helper.color_red,
            )
        else:
            run_subdomain_scan(args.domain, wordlist, threads, helper)

    helper.log(
        f'\nAnalysis complete.', helper.color_yellow + helper.color_bold
    )


if __name__ == '__main__':
    main()
