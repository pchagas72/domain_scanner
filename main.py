import argparse
import os
import threading
import json
from queue import Queue

from utils.helper import Helper

from scanners.whois_scanner import get_whois_and_ip_info
from scanners.ssl_scanner import get_ssl_certificate_info
from scanners.subdomain_scanner import run_subdomain_scan
from scanners.hunter_scanner import find_emails_with_hunter
from scanners.tech_scanner import analyze_technologies
from scanners.port_scanner import scan_ports
from scanners.dns_scanner import get_dns_records


def subdomain_scan_worker(q, results, lock):
    """
        Worker function to process subdomains and store results.
    """
    while not q.empty():
        subdomain = q.get()
        tech_results = analyze_technologies(subdomain, None)
        port_results = scan_ports(subdomain, None)
        with lock:
            results[subdomain] = {'tech': tech_results, 'ports': port_results}
        q.task_done()

def main():
    """
        Parses arguments and runs the selected scans.
    """

    parser = argparse.ArgumentParser(description='All-in-one domain analysis tool.')

    parser.add_argument('domain', help='The target domain to analyze.')
    parser.add_argument('--whois', action='store_true', help='Perform WHOIS and IP lookup.')
    parser.add_argument('--hunter', action='store_true', help='Perform HUNTER email lookup.')
    parser.add_argument('--ssl', action='store_true', help='Perform SSL certificate scan.')
    parser.add_argument('--subdomains', action='store_true', help='Perform a subdomain scan.')
    parser.add_argument('--tech', action='store_true', help='Perform web technology analysis.')
    parser.add_argument('--ports', action='store_true', help='Perform a common port scan.')
    parser.add_argument('--dns', action='store_true', help='Perform a DNS records scan.')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for subdomain scan.')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads for subdomain scan.')
    parser.add_argument('--scan-subdomains', action='store_true', help='Run tech and port scans on all discovered subdomains.')
    parser.add_argument('--sub-threads', type=int, default=20, help='Number of threads for scanning subdomains (default: 20).')
    parser.add_argument('--ipinfo-key', help='API key for ipinfo.io for better output.')
    parser.add_argument('--hunter-key', help='API key for hunter.io for email searching.')
    parser.add_argument('--config', help='Path to a .env configuration file.')
    parser.add_argument('--output', help='Path to save the text output to a file.')
    parser.add_argument('--json', nargs='?', const='{domain}_output.json', default=None, help='Export results to a JSON file. Optionally specify a filename.')
    
    args = parser.parse_args()
    helper = Helper()
    master_results = {'domain': args.domain, 'scans': {}}

    if args.output:
        helper.output_path = args.output

    if args.config:
        helper.read_config_env(args.config)

    ipinfo_key = args.ipinfo_key or helper.config.get('IPINFO_API_KEY')
    hunter_key = args.hunter_key or helper.config.get('HUNTER_API_KEY')
    wordlist = args.wordlist or helper.config.get('WORDLIST_PATH') or 'config/subdomains.txt'
    # Check config.env, also make more use of that file
    threads = args.threads or int(helper.config.get('THREADS', 50))

    run_all = not any([args.whois, args.ssl, args.subdomains,
                       args.hunter, args.tech, args.ports, args.dns])

    helper.log(f'\nStarting analysis for: {args.domain}', helper.color_yellow + helper.color_bold)
    
    if args.tech or run_all:
        master_results['scans']['tech'] = analyze_technologies(args.domain, helper)

    if args.ports or run_all:
        master_results['scans']['ports'] = scan_ports(args.domain, helper)

    if args.whois or run_all:
        master_results['scans']['whois_ipinfo'] = get_whois_and_ip_info(args.domain, ipinfo_key, helper)

    if args.dns or run_all:
        master_results['scans']['dns'] = get_dns_records(args.domain, helper)

    if args.ssl or run_all:
        master_results['scans']['ssl'] = get_ssl_certificate_info(args.domain, helper=helper)

    if args.hunter or run_all:
        master_results['scans']['hunter'] = find_emails_with_hunter(args.domain, hunter_key, helper)

    discovered_subdomains = []
    if args.subdomains or run_all:
        discovered_subdomains = run_subdomain_scan(args.domain, wordlist, threads, helper)
        master_results['scans']['discovered_subdomains'] = discovered_subdomains

    if args.scan_subdomains and discovered_subdomains:
        helper.log(f'\n--- Starting Port and Tech Scan for {len(discovered_subdomains)} Discovered Subdomains ---', helper.color_yellow + helper.color_bold)
        q = Queue()
        for subdomain in discovered_subdomains:
            if subdomain.lower() != args.domain.lower():
                q.put(subdomain)

        scan_results = {}
        lock = threading.Lock()
        threads_list = []
        for _ in range(args.sub_threads):
            worker = threading.Thread(target=subdomain_scan_worker, args=(q, scan_results, lock))
            worker.daemon = True
            worker.start()
            threads_list.append(worker)
        q.join()
        
        master_results['scans']['subdomain_details'] = scan_results

        for subdomain, results in sorted(scan_results.items()):
             helper.log(f'\n--- Results for {subdomain} ---', helper.color_yellow)
             tech = results.get('tech', {})
             if tech.get('found'):
                 helper.log('[+] Technologies found:', helper.color_green)
                 for t in sorted(tech['found']): helper.log(f'  - {t}', helper.color_blue)
             ports = results.get('ports', {})
             if ports.get('open'):
                 helper.log('[+] Open ports found:', helper.color_green)
                 for p in sorted(ports['open']): helper.log(f'  - {p}', helper.color_blue)

    if args.json:
        filename = args.json.format(domain=args.domain)
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(master_results, f, indent=4, default=str)
            helper.log(f'\n[+] Results exported to JSON: {filename}', helper.color_green)
        except Exception as e:
            helper.log(f'\n[-] Error exporting to JSON: {e}', helper.color_red)

    helper.log(f'\nAnalysis complete.', helper.color_yellow + helper.color_bold)

if __name__ == '__main__':
    main()
