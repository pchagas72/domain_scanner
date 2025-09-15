import socket
import threading
from queue import Queue
import time
from utils.helper import log_info, log_error, log_success


def _scan_subdomain_worker(domain, q, discovered_subdomains, lock, helper):
    """The worker function for the subdomain scanning threads."""
    while not q.empty():
        subdomain = q.get()
        full_url = f'{subdomain}.{domain}'
        try:
            ip_address = socket.gethostbyname(full_url)
            with lock:
                log_success(
                    f'[+] Discovered: {full_url.ljust(35)} (IP: {ip_address})',
                    helper,
                )
                discovered_subdomains.append(full_url)
        except socket.gaierror:
            pass
        finally:
            q.task_done()


def run_subdomain_scan(domain, wordlist_file, num_threads, helper):
    """Orchestrates the multi-threaded subdomain scan."""
    log_info(f'\n--- Scanning for Subdomains ---', helper)
    log_info(
        f'[*] Target: {domain} | Wordlist: {wordlist_file} | Threads: {num_threads}',
        helper,
    )

    q = Queue()
    discovered_subdomains = []
    lock = threading.Lock()

    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                subdomain = line.strip()
                if subdomain:
                    q.put(subdomain)
    except FileNotFoundError:
        log_error(f"Error: Wordlist file '{wordlist_file}' not found.", helper)
        return

    total_subdomains = q.qsize()
    if total_subdomains == 0:
        log_error('Wordlist is empty. Aborting subdomain scan.', helper)
        return

    log_info(f'[*] Loaded {total_subdomains} potential subdomains.', helper)
    start_time = time.time()

    threads = []
    for _ in range(num_threads):
        worker = threading.Thread(
            target=_scan_subdomain_worker,
            args=(domain, q, discovered_subdomains, lock, helper),
        )
        worker.daemon = True
        worker.start()
        threads.append(worker)

    q.join()

    end_time = time.time()
    log_info('\n--- Subdomain Scan Complete ---', helper)
    log_info(f'Total time taken: {end_time - start_time:.2f} seconds', helper)
    log_info(f'Discovered {len(discovered_subdomains)} subdomains.', helper)

    if discovered_subdomains:
        output_file = f'{domain}_subdomains.txt'
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for sub in sorted(discovered_subdomains):
                    f.write(sub + '\n')
                log_success(f'[+] Subdomain results saved to {output_file}', helper)
        except IOError:
            log_error(f"Could not write to subdomain output file: {output_file}", helper)

    return discovered_subdomains # Add this return statement at the end
