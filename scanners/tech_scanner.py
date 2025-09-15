import requests
from bs4 import BeautifulSoup
from utils.helper import log_info, log_error, log_success, log_warning, resolve_domain
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- (TECH_SIGNATURES dictionary is the same) ---
TECH_SIGNATURES = {
    # --- Server & CDN ---
    'nginx': {'server_header': 'nginx'},
    'Apache': {'server_header': 'Apache'},
    'Cloudflare': {'server_header': 'cloudflare'},
    'LiteSpeed': {'server_header': 'LiteSpeed'},
    'Microsoft-IIS': {'server_header': 'Microsoft-IIS'},

    # --- CMS ---
    'WordPress': {'meta_generator': 'WordPress', 'html_content': '/wp-content/'},
    'Joomla': {'meta_generator': 'Joomla!'},
    'Drupal': {'meta_generator': 'Drupal'},
    'Squarespace': {'html_content': 'Squarespace'},
    'Wix': {'html_content': 'wix.com'},

    # --- E-commerce ---
    'Shopify': {'html_content': 'cdn.shopify.com'},
    'Magento': {'html_content': 'Magento', 'script_src': 'mage/'},
    'WooCommerce': {'html_content': 'woocommerce'},

    # --- JavaScript Frameworks & Libraries ---
    'React': {'html_content': 'data-reactroot'},
    'Vue.js': {'html_content': 'data-v-app'},
    'Angular': {'html_content': 'ng-version'},
    'jQuery': {'script_src': 'jquery.js'},

    # --- Analytics ---
    'Google Analytics': {'script_src': 'google-analytics.com/analytics.js'},
    
    # --- Server-side Languages ---
    'PHP': {'header': ('X-Powered-By', 'PHP')},
    'ASP.NET': {'header': ('X-AspNet-Version', None)}
}

def analyze_technologies(domain, helper):
    """Analyzes the technology stack of a given domain with more specific checks."""
    # If helper is None, we are in worker mode and should not print
    is_worker = helper is None
    
    if not is_worker:
        log_info(f'\n--- Analyzing Web Technologies for {domain} ---', helper)
    
    # We pass a dummy helper if in worker mode to avoid errors in resolve_domain
    temp_helper = helper if helper else type('DummyHelper', (), {'log': lambda *args: None})()
    
    _, resolved_name = resolve_domain(domain, temp_helper)
    if not resolved_name:
        if not is_worker:
            log_error(f'Could not resolve {domain} to connect for tech scan.', helper)
        return {'found': set()}

    url = f'https://{resolved_name}'
    found_techs = set()
    try:
        # It's better to ignore SSL verification errors in an OSINT tool
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
        
        html_content = response.text
        response_headers = response.headers

        # ... (All the detection logic remains exactly the same) ...
        # Check Server Headers (Server, X-Powered-By, etc.)
        for tech, sigs in TECH_SIGNATURES.items():
            if 'server_header' in sigs and 'Server' in response_headers:
                if sigs['server_header'].lower() in response_headers['Server'].lower():
                    found_techs.add(tech)
            if 'header' in sigs:
                header_name, header_value = sigs['header']
                if header_name in response_headers:
                    if header_value is None or header_value.lower() in response_headers[header_name].lower():
                        found_techs.add(tech)

        # Check the entire HTML for content signatures
        for tech, sigs in TECH_SIGNATURES.items():
            if 'html_content' in sigs and sigs['html_content'] in html_content:
                found_techs.add(tech)

        # Parses html
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Check for meta generator tags
        generator_tag = soup.find('meta', attrs={'name': 'generator'})
        if generator_tag and generator_tag.get('content'):
            content = generator_tag.get('content')
            for tech, sigs in TECH_SIGNATURES.items():
                if 'meta_generator' in sigs and sigs['meta_generator'].lower() in content.lower():
                    found_techs.add(tech)
        
        # Check for specific script sources
        script_tags = soup.find_all('script')
        for script in script_tags:
            src = script.get('src', '')
            for tech, sigs in TECH_SIGNATURES.items():
                if 'script_src' in sigs and sigs['script_src'] in src:
                    found_techs.add(tech)


        if not is_worker:
            if found_techs:
                log_success(f'[+] Technologies found for {domain}:', helper)
                for tech in sorted(list(found_techs)):
                    log_info(f'  - {tech}', helper)
            else:
                log_warning(f'[-] No specific technologies identified for {domain}.', helper)
        
        return {'found': found_techs}

    except requests.RequestException:
        if not is_worker:
            log_error(f'Could not connect to {url}', helper)
        return {'found': set()}
