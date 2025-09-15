import socket
import threading
from queue import Queue
from utils.helper import log_info, log_error, log_success, resolve_domain

# Expand if needed, or add to config file
COMMON_PORTS = [21, 22, 25, 53, 80, 443, 3306, 8080, 8443]

def _port_worker(target_ip, port_q, open_ports, lock):
    """Worker function for the multi-threaded port scan."""
    while not port_q.empty():
        port = port_q.get()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)
        
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            with lock:
                open_ports.append(port)
        
        sock.close()
        port_q.task_done()

def scan_ports(domain, helper):
    """
        Scans for common open ports on the target domain using threads.
    """
    is_worker = helper is None

    # This is just a method of not clogging the output
    if not is_worker:
        log_info(f'\n--- Scanning Common Ports for {domain} ---', helper)

    temp_helper = helper if helper else type('DummyHelper', (), {'log': lambda *args: None})()
    
    # This is needed because some domains x.com have their pages at www.x.com but 
    # do not direct from x.com to www.x.com
    target_ip, resolved_name = resolve_domain(domain, temp_helper)
    if not target_ip:
        if not is_worker:
            log_error(f'Hostname could not be resolved for {domain}.', helper)
        return {'open': []}

    if not is_worker:
        if domain != resolved_name:
            log_info(f'[*] Resolved {domain} to {resolved_name} ({target_ip})', helper)
        else:
            log_info(f'[*] Resolved {domain} to IP: {target_ip}', helper)

    port_q = Queue()
    for port in COMMON_PORTS:
        port_q.put(port)
        
    open_ports = []
    lock = threading.Lock()
    threads = []
    
    for _ in range(len(COMMON_PORTS)):
        thread = threading.Thread(target=_port_worker, args=(target_ip, port_q, open_ports, lock))
        thread.daemon = True
        thread.start()
        threads.append(thread)
        
    port_q.join()

    if not is_worker:
        if open_ports:
            for port in sorted(open_ports):
                 log_success(f'  [+] Port {port} is open', helper)
        else:
            log_error(f'[-] No common ports found open for {domain}.', helper)
    
    return {'open': open_ports}
