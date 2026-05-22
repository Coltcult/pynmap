#!/usr/bin/env python3
"""
PyNmap v2.0 - Network Scanner with Reinforcement Learning and Payload Evolution
Enhanced version with bug fixes
"""

import sys
sys.path.insert(0, "/mnt/sdcard/tools/python-packages/extracted")
import socket
import threading
import re
import json
import argparse
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom

# Try to import learning modules, but don't fail if not available
try:
    from pynmap_learning import (
        ReinforcementLearner, 
        PayloadEvolution, 
        ScanMemory, 
        FlagDetector,
        LearningStats
    )
    LEARNING_AVAILABLE = True
except ImportError:
    LEARNING_AVAILABLE = False
    print("[WARN] Learning modules not available - run without learning")

# --- ANSI Color Codes for Pretty Printing ---
class Colors:
    RESET = '\033[0m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'

# ==============================================================================
# === PURE PYTHON SCRIPTING ENGINE (LIKE NSE) =================================
# ==============================================================================

class ScriptManager:
    """Loads, categorizes, and runs Python-based 'NSE' scripts."""
    def __init__(self):
        self._scripts = {}
        self._categories = {}
        self._load_scripts()

    def _load_scripts(self):
        """Finds and registers all functions decorated as scripts."""
        for name, func in globals().items():
            if hasattr(func, '_is_script'):
                script_name = func._script_name
                self._scripts[script_name] = func
                category = func._category
                if category not in self._categories:
                    self._categories[category] = []
                self._categories[category].append(script_name)

    def get_scripts(self, selection):
        """Returns script functions based on user selection."""
        if not selection:
            return []

        selected_scripts = set()
        for item in selection.split(','):
            item = item.strip()
            if item in self._scripts:
                selected_scripts.add(self._scripts[item])
            elif item in self._categories:
                for script_name in self._categories[item]:
                    selected_scripts.add(self._scripts[script_name])
            elif item == 'all':
                return list(self._scripts.values())

        if 'default' in selection:
            for script_name in self._categories.get('safe', []):
                selected_scripts.add(self._scripts[script_name])

        return list(selected_scripts)


def nse_script(name, category='safe'):
    def decorator(func):
        func._is_script = True
        func._script_name = name
        func._category = category
        return func
    return decorator


# --- Existing Script Implementations ---

@nse_script("http-title", category="discovery")
def script_http_title(target_ip, port, payload=None):
    """Sends a GET request and extracts the <title> from the HTML response."""
    try:
        with socket.create_connection((target_ip, port), timeout=3) as s:
            request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\nUser-Agent: PyNmap/1.0\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(2048).decode(errors='ignore')
            match = re.search(r'<title>(.*?)</title>', response, re.IGNORECASE | re.DOTALL)
            if match:
                return {"title": match.group(1).strip()}
    except Exception:
        return None

@nse_script("ftp-anon", category="vuln")
def script_ftp_anon(target_ip, port, payload=None):
    """Checks if anonymous FTP login is allowed."""
    try:
        with socket.create_connection((target_ip, port), timeout=3) as s:
            s.recv(1024)
            s.sendall(b"USER anonymous\r\n")
            if "331" not in s.recv(1024).decode(): return None
            s.sendall(b"PASS anonymous@pynmap.com\r\n")
            if "230" in s.recv(1024).decode():
                return {"Vulnerable": "Anonymous FTP login is allowed."}
    except Exception:
        return None

@nse_script("http-headers", category="discovery")
def script_http_headers(target_ip, port, payload=None):
    """Grabs HTTP headers."""
    try:
        with socket.create_connection((target_ip, port), timeout=3) as s:
            request = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\nUser-Agent: PyNmap/1.0\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(2048).decode(errors='ignore')
            headers = {}
            for line in response.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            return headers if headers else None
    except Exception:
        return None

@nse_script("http-security-headers", category="vuln")
def script_http_security_headers(target_ip, port, payload=None):
    """Checks for missing security headers."""
    headers = script_http_headers(target_ip, port)
    if not headers:
        return None

    missing_headers = []
    expected = {
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Referrer-Policy'
    }
    present_headers = {h.lower() for h in headers.keys()}
    for h in expected:
        if h.lower() not in present_headers:
            missing_headers.append(h)

    return {"Missing Headers": missing_headers} if missing_headers else None

@nse_script("dns-brute", category="discovery")
def script_dns_brute(target_ip, port, payload=None):
    """DNS brute-force placeholder."""
    return None

@nse_script("smb-os-discovery", category="discovery")
def script_smb_os_discovery(target_ip, port, payload=None):
    """Attempts SMB OS discovery."""
    try:
        with socket.create_connection((target_ip, port), timeout=3) as s:
            packet = (
                b'\x00\x00\x00\x85'
                b'\xff\x53\x4d\x42'
                b'\x72'
                b'\x00\x00\x00\x00'
                b'\x18\x53\xc8\x17'
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe'
                b'\x00\x00\x00\x00'
                b'\x00\x62'
                b'\x00'
                b'\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00'
                b'\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
            )
            s.send(packet)
            response = s.recv(1024)
            strings = response[32:].split(b'\x00')
            decoded_strings = [st.decode('utf-8', 'ignore') for st in strings if st]
            if decoded_strings:
                return {"Discovered Strings": decoded_strings}
    except Exception:
        return None

# ==============================================================================
# === MAIN PY-NMAP SCANNER CLASS ===============================================
# ==============================================================================

class PyNmapScanner:
    def __init__(self, targets, ports, scripts_to_run, timing, verbosity, learn=False):
        self.targets = targets
        self.ports_to_scan = ports
        self.scripts_to_run = scripts_to_run
        self.timing = timing
        self.verbosity = verbosity
        self.results = {}
        self.learn = learn and LEARNING_AVAILABLE
        
        # Initialize learning systems if enabled
        if self.learn:
            self.reinforcement = ReinforcementLearner()
            self.evolution = PayloadEvolution()
            self.memory = ScanMemory()
            self.learning_stats = {
                'attacks_tried': 0,
                'successful_attacks': 0,
                'flags_found': 0,
                'start_time': time.time()
            }
            print(f"{Colors.CYAN}[LEARN] Learning mode enabled - I will improve over time{Colors.RESET}")
        else:
            self.reinforcement = None
            self.evolution = None
            self.memory = None

    def _vprint(self, message, level=1):
        if self.verbosity >= level:
            print(message)

    def _scan_port(self, target_ip, port):
        """TCP Connect scan."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timing['timeout'])
                if s.connect_ex((target_ip, port)) == 0:
                    banner = ""
                    try:
                        banner_bytes = s.recv(1024)
                        banner = banner_bytes.decode('utf-8', 'ignore').strip()
                    except (socket.timeout, ConnectionResetError):
                        pass
                    return port, banner
        except (socket.error, OverflowError):
            pass
        return None

    def _run_dns_brute(self, domain):
        """DNS brute-force for subdomains."""
        self._vprint(f"[*] Starting DNS brute-force on {domain}...")
        subdomains = ['www', 'mail', 'ftp', 'test', 'dev', 'admin', 'api', 'vpn', 'webmail']
        found = []
        for sub in subdomains:
            try:
                host = f"{sub}.{domain}"
                ip = socket.gethostbyname(host)
                found.append(f"{host} - {ip}")
                self._vprint(f"{Colors.GREEN}[+] Found: {host} -> {ip}{Colors.RESET}")
            except socket.gaierror:
                pass
        return {"subdomains": found} if found else None

    def calculate_reward(self, script_result, duration):
        """Calculate reward for reinforcement learning."""
        if not script_result:
            return -0.1
        
        reward = 10
        
        result_str = str(script_result).lower()
        if 'vulnerable' in result_str or 'vulnerability' in result_str:
            reward += 30
        if 'credential' in result_str or 'password' in result_str:
            reward += 20
        if LEARNING_AVAILABLE and FlagDetector.contains_flag(script_result):
            reward += 50
        
        if duration < 1:
            reward += 5
        elif duration > 10:
            reward -= 2
        
        return reward

    def run_scan(self):
        script_manager = ScriptManager()
        scripts = script_manager.get_scripts(self.scripts_to_run)
        
        # Get optimal script order if learning enabled
        if self.learn and self.reinforcement:
            target_context = {'open_ports': [], 'services': {}}
            scripts = self.reinforcement.get_optimal_sequence(target_context, scripts)
        
        for target in self.targets:
            # Define start_time here for each target
            target_start_time = time.time()
            
            try:
                target_ip = socket.gethostbyname(target)
                print(f"\n{Colors.BLUE}Starting PyNmap scan for {target} ({target_ip}){Colors.RESET}")
                self.results[target] = {'ip': target_ip, 'ports': {}, 'host_scripts': {}}
            except socket.gaierror:
                print(f"{Colors.RED}[!] Cannot resolve hostname: {target}. Skipping.{Colors.RESET}")
                continue

            # --- Port Scanning Phase ---
            ports_to_scan = self.ports_to_scan
            if self.learn and self.reinforcement:
                ports_to_scan = self.reinforcement.prioritize_ports(ports_to_scan, {})
            
            with ThreadPoolExecutor(max_workers=self.timing['workers']) as executor:
                future_to_port = {executor.submit(self._scan_port, target_ip, port): port for port in ports_to_scan}
                for future in as_completed(future_to_port):
                    res = future.result()
                    if res:
                        port, banner = res
                        service_name = 'unknown'
                        try:
                            service_name = socket.getservbyport(port)
                        except OSError: 
                            pass
                        self.results[target]['ports'][port] = {
                            'state': 'open',
                            'service': service_name,
                            'banner': banner,
                            'scripts': {}
                        }

            # --- Scripting Phase with Learning ---
            for port, port_data in self.results[target]['ports'].items():
                service_context = {
                    'port': port,
                    'service': port_data['service'],
                    'banner': port_data['banner']
                }
                
                for script in scripts:
                    if script.__name__ == 'script_dns_brute':
                        continue
                    
                    # Get evolved payload if learning
                    evolved_payload = None
                    if self.learn and self.evolution:
                        evolved_payload = self.evolution.get_payload(script._script_name, service_context)
                    
                    self._vprint(f"[*] Running script '{script._script_name}' on {target_ip}:{port}", 2)
                    
                    script_start = time.time()
                    try:
                        script_res = script(target_ip, port, evolved_payload)
                    except TypeError:
                        # Fallback if script doesn't accept payload parameter
                        script_res = script(target_ip, port)
                    script_duration = time.time() - script_start
                    
                    if self.learn:
                        self.learning_stats['attacks_tried'] += 1
                        reward = self.calculate_reward(script_res, script_duration)
                        self.reinforcement.update(service_context, script._script_name, reward)
                        
                        if script_res:
                            self.learning_stats['successful_attacks'] += 1
                            self.memory.record_attack_result(script._script_name, True)
                            
                            # Check for flags
                            if LEARNING_AVAILABLE and FlagDetector.contains_flag(script_res):
                                flags = FlagDetector.extract_flags(script_res)
                                self.learning_stats['flags_found'] += len(flags)
                                for flag_info in flags:
                                    self.memory.record_flag(flag_info['flag'])
                                FlagDetector.print_flags(flags)
                            
                            if self.evolution and evolved_payload:
                                self.evolution.update(evolved_payload, {'success': True, 'result': script_res})
                        else:
                            self.memory.record_attack_result(script._script_name, False)
                            if self.evolution and evolved_payload:
                                self.evolution.update(evolved_payload, {'success': False})
                    
                    if script_res:
                        self.results[target]['ports'][port]['scripts'][script._script_name] = script_res

            # --- Host Script Phase ---
            for script in scripts:
                if script.__name__ == 'script_dns_brute':
                    res = self._run_dns_brute(target)
                    if res:
                        self.results[target]['host_scripts']['dns-brute'] = res
                        if self.learn and LEARNING_AVAILABLE and FlagDetector.contains_flag(res):
                            flags = FlagDetector.extract_flags(res)
                            FlagDetector.print_flags(flags)
            
            # --- Store results in memory if learning ---
            if self.learn and self.memory:
                scan_results = {
                    'open_ports': list(self.results[target]['ports'].keys()),
                    'services': {p: d['service'] for p, d in self.results[target]['ports'].items()}
                }
                self.memory.store_scan_result(target, scan_results, time.time() - target_start_time)
        
        # --- Print learning statistics ---
        if self.learn and self.learning_stats['attacks_tried'] > 0:
            elapsed = time.time() - self.learning_stats['start_time']
            print(f"\n{Colors.CYAN}[LEARN] Session Statistics:{Colors.RESET}")
            print(f"  Attacks attempted: {self.learning_stats['attacks_tried']}")
            if self.learning_stats['attacks_tried'] > 0:
                print(f"  Success rate: {self.learning_stats['successful_attacks']/self.learning_stats['attacks_tried']*100:.1f}%")
            print(f"  Flags found: {self.learning_stats['flags_found']}")
            print(f"  Time spent: {elapsed:.1f}s")
            
            # Save learning data
            if self.reinforcement:
                self.reinforcement.save_q_table()
            if self.evolution:
                self.evolution.save_population()
            if self.memory and LEARNING_AVAILABLE:
                LearningStats.print_stats(self.reinforcement, self.evolution, self.memory)


# ==============================================================================
# === OUTPUT FORMATTERS ========================================================
# ==============================================================================

def save_normal(results, filename):
    if filename == 'con':
        return
    with open(filename, 'w') as f:
        for target, data in results.items():
            f.write(f"Scan Report for {target} ({data['ip']})\n")
            f.write("----------------------------------------------\n")
            ports = data.get('ports', {})
            if not ports:
                f.write("No open ports found.\n")
            else:
                f.write("PORT\tSTATE\tSERVICE\n")
                sorted_ports = sorted(ports.keys())
                for port in sorted_ports:
                    info = ports[port]
                    f.write(f"{port}/tcp\t{info['state']}\t{info['service']}\n")
                    if info.get('banner'):
                        f.write(f"|  Banner: {info['banner']}\n")
                    for s_name, s_res in info.get('scripts', {}).items():
                        f.write(f"|  {s_name}:\n")
                        for k, v in s_res.items():
                            f.write(f"|    {k}: {v}\n")

            host_scripts = data.get('host_scripts', {})
            for s_name, s_res in host_scripts.items():
                 f.write(f"\nHost script: {s_name}\n")
                 for k, v in s_res.items():
                     f.write(f"  {k}: {v}\n")
            f.write("\n")

def save_json(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)

def save_xml(results, filename):
    root = Element('pynmaprun')
    for target, data in results.items():
        host = SubElement(root, 'host')
        address = SubElement(host, 'address', {'addr': data['ip'], 'addrtype': 'ipv4'})
        ports = SubElement(host, 'ports')
        for port_num, info in data.get('ports', {}).items():
            port = SubElement(ports, 'port', {'protocol': 'tcp', 'portid': str(port_num)})
            SubElement(port, 'state', {'state': info['state']})
            SubElement(port, 'service', {'name': info['service'], 'banner': info.get('banner', '')})
            scripts = SubElement(port, 'scripts')
            for s_name, s_res in info.get('scripts', {}).items():
                SubElement(scripts, 'script', {'id': s_name, 'output': json.dumps(s_res)})

    xml_str = minidom.parseString(tostring(root)).toprettyxml(indent="  ")
    with open(filename, 'w') as f:
        f.write(xml_str)


# ==============================================================================
# === MAIN EXECUTION ===========================================================
# ==============================================================================

def parse_ports(port_str):
    """Parses a nmap-style port string."""
    ports = set()
    if not port_str: 
        return []
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def main():
    parser = argparse.ArgumentParser(description="PyNmap v2.0 - Network Scanner with Reinforcement Learning",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('targets', metavar='<target>', nargs='+', help='Target hosts or domains')
    parser.add_argument('-p', '--ports', default="21,22,25,53,80,110,139,443,445,3306,3389,8080,8443",
                        help="Ports to scan")
    parser.add_argument('--script', help="Scripts to run (e.g., 'http-headers,vuln' or 'default')")
    
    # Learning flags
    parser.add_argument('--learn', action='store_true', help="Enable reinforcement learning")
    parser.add_argument('--show-stats', action='store_true', help="Show learning statistics")

    timing_group = parser.add_argument_group('timing and performance')
    timing_group.add_argument('-T', '--timing', type=int, choices=range(6), default=4,
                              help="Set timing template (0-5)")

    output_group = parser.add_argument_group('output')
    output_group.add_argument('-oN', '--output-normal', metavar='<file>', help="Save output in normal format.")
    output_group.add_argument('-oJ', '--output-json', metavar='<file>', help="Save output in JSON format.")
    output_group.add_argument('-oX', '--output-xml', metavar='<file>', help="Save output in XML format.")

    parser.add_argument('-v', '--verbose', action='count', default=0, help="Increase verbosity level")

    args = parser.parse_args()

    timings = {
        0: {'workers': 1, 'timeout': 10.0}, 1: {'workers': 5, 'timeout': 5.0},
        2: {'workers': 20, 'timeout': 2.0}, 3: {'workers': 50, 'timeout': 1.5},
        4: {'workers': 100, 'timeout': 1.0}, 5: {'workers': 250, 'timeout': 0.5},
    }

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(f"{Colors.RED}[!] Invalid port format.{Colors.RESET}")
        sys.exit(1)

    scanner = PyNmapScanner(args.targets, ports, args.script, timings[args.timing], args.verbose, args.learn)
    overall_start = time.time()
    
    try:
        scanner.run_scan()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user.{Colors.RESET}")
        sys.exit(1)

    overall_end = time.time()
    results = scanner.results

    # Print normal output to console
    print(f"\n{Colors.BLUE}PyNmap scan report summary:{Colors.RESET}")
    for target, data in results.items():
        print(f"\nHost: {Colors.CYAN}{target} ({data['ip']}){Colors.RESET}")
        ports_data = data.get('ports', {})
        if not ports_data:
            print("  No open ports found in scanned range.")
        else:
            print(f"  {'PORT':<8}{'STATE':<8}{'SERVICE':<15}{'DETAILS'}")
            for port in sorted(ports_data.keys()):
                info = ports_data[port]
                banner_preview = info.get('banner', '')[:50]
                print(f"  {Colors.GREEN}{port:<8}{info['state']:<8}{info['service']:<15}{Colors.RESET}{banner_preview}")
                for s_name, s_res in info.get('scripts', {}).items():
                    print(f"  {Colors.YELLOW}|_ {s_name}:{Colors.RESET}")
                    for k, v in s_res.items():
                        print(f"     {k}: {str(v)[:100]}")

        host_scripts = data.get('host_scripts', {})
        for s_name, s_res in host_scripts.items():
            print(f"\n  {Colors.YELLOW}Host Script: {s_name}{Colors.RESET}")
            for k, v in s_res.items():
                print(f"    {k}: {v}")

    # Save to files if requested
    if args.output_normal:
        save_normal(results, args.output_normal)
        print(f"\n[+] Normal output saved to: {args.output_normal}")
    if args.output_json:
        save_json(results, args.output_json)
        print(f"[+] JSON output saved to: {args.output_json}")
    if args.output_xml:
        save_xml(results, args.output_xml)
        print(f"[+] XML output saved to: {args.output_xml}")

    print(f"\nPyNmap done: {len(args.targets)} host(s) scanned in {overall_end - overall_start:.2f} seconds")
    
    # Show learning stats if requested
    if args.show_stats and args.learn and scanner.memory and LEARNING_AVAILABLE:
        LearningStats.print_stats(scanner.reinforcement, scanner.evolution, scanner.memory)

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
Additional NSE-style scripts for PyNmap
To be appended to pynmap_v2_fixed.py
"""

# ==============================================================================
# === WEB APPLICATION SCRIPTS ==================================================
# ==============================================================================

@nse_script("http-sql-injection", category="vuln")
def script_http_sql_injection(target_ip, port, payload=None):
    """Tests for SQL injection vulnerabilities."""
    test_payloads = payload or [
        "' OR '1'='1", "' OR 1=1 --", "1' AND '1'='1", 
        "admin' --", "' UNION SELECT NULL--", "1' OR '1'='1' --"
    ]
    
    try:
        with socket.create_connection((target_ip, port), timeout=5) as s:
            for test_payload in (test_payloads if isinstance(test_payloads, list) else [test_payloads]):
                request = f"GET /?id={test_payload} HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode())
                response = s.recv(4096).decode(errors='ignore')
                
                sql_errors = [
                    'sql syntax', 'mysql_fetch', 'ora-', 'postgresql error', 
                    'unclosed quotation', 'microsoft ole db', 'odbc driver',
                    'you have an error in your sql', 'warning: mysql',
                    'syntax error', 'invalid query', 'division by zero'
                ]
                
                for error in sql_errors:
                    if error.lower() in response.lower():
                        return {"Vulnerable": True, "Type": "SQL Injection", "Payload": test_payload}
    except Exception:
        pass
    return None

@nse_script("http-lfi", category="vuln")
def script_http_lfi(target_ip, port, payload=None):
    """Tests for Local File Inclusion."""
    test_payloads = payload or [
        "../../../etc/passwd",
        "../../../../etc/passwd", 
        "../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../../windows/win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "..;/..;/..;/etc/passwd",
        "....///....///....///etc/passwd"
    ]
    
    try:
        with socket.create_connection((target_ip, port), timeout=5) as s:
            for test_payload in (test_payloads if isinstance(test_payloads, list) else [test_payloads]):
                for param in ['page', 'file', 'path', 'include', 'doc', 'folder', 'root']:
                    request = f"GET /?{param}={test_payload} HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                    s.sendall(request.encode())
                    response = s.recv(8192).decode(errors='ignore')
                    
                    if 'root:' in response and ('/bin/bash' in response or '/bin/sh' in response):
                        return {"Vulnerable": True, "Type": "LFI", "File": "/etc/passwd", "Payload": test_payload, "Parameter": param}
                    if '[extensions]' in response and 'fonts' in response:
                        return {"Vulnerable": True, "Type": "LFI", "File": "win.ini", "Payload": test_payload, "Parameter": param}
    except Exception:
        pass
    return None

@nse_script("http-xss", category="vuln")
def script_http_xss(target_ip, port, payload=None):
    """Tests for Reflected XSS."""
    test_payloads = payload or [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "javascript:alert('XSS')",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "><script>alert(1)</script>"
    ]
    
    try:
        with socket.create_connection((target_ip, port), timeout=5) as s:
            for test_payload in (test_payloads if isinstance(test_payloads, list) else [test_payloads]):
                for param in ['q', 's', 'search', 'query', 'id', 'page']:
                    request = f"GET /?{param}={test_payload} HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                    s.sendall(request.encode())
                    response = s.recv(4096).decode(errors='ignore')
                    
                    if test_payload in response:
                        return {"Vulnerable": True, "Type": "XSS", "Payload": test_payload, "Parameter": param}
    except Exception:
        pass
    return None

@nse_script("http-git", category="discovery")
def script_http_git(target_ip, port, payload=None):
    """Checks for exposed .git directory."""
    git_paths = ['/.git/config', '/.git/HEAD', '/.git/index', '/.git/logs/HEAD']
    
    try:
        with socket.create_connection((target_ip, port), timeout=5) as s:
            for path in git_paths:
                request = f"GET {path} HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode())
                response = s.recv(4096).decode(errors='ignore')
                
                if 'repositoryformatversion' in response or 'ref: refs/heads/' in response:
                    return {"Exposed": True, "Type": "Git Repository", "Path": path}
    except Exception:
        pass
    return None

@nse_script("http-enum", category="discovery")
def script_http_enum(target_ip, port, payload=None):
    """Enumerates common web paths."""
    common_paths = [
        "/admin", "/login", "/wp-admin", "/administrator", "/phpmyadmin",
        "/backup", "/old", "/test", "/dev", "/api", "/config", "/secret",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/flag", "/flag.txt",
        "/.env", "/.git", "/.svn", "/backup.zip", "/backup.tar.gz", "/dump.sql",
        "/phpinfo.php", "/info.php", "/server-status", "/cgi-bin/", "/shell"
    ]
    
    found_paths = []
    try:
        with socket.create_connection((target_ip, port), timeout=5) as s:
            for path in common_paths:
                request = f"GET {path} HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode())
                response = s.recv(4096).decode(errors='ignore')
                
                if '200 OK' in response:
                    found_paths.append(f"{path} (200)")
                elif '403 Forbidden' in response:
                    found_paths.append(f"{path} (403)")
                elif '401 Unauthorized' in response:
                    found_paths.append(f"{path} (401)")
    except Exception:
        pass
    
    return {"Discovered Paths": found_paths} if found_paths else None

# ==============================================================================
# === VULNERABILITY SCRIPTS ====================================================
# ==============================================================================

@nse_script("http-shellshock", category="vuln")
def script_http_shellshock(target_ip, port, payload=None):
    """Tests for Shellshock vulnerability (CVE-2014-6271)."""
    test_headers = [
        ("User-Agent", "() { :; }; echo vulnerable"),
        ("Referer", "() { :; }; echo vulnerable"),
        ("Cookie", "() { :; }; echo vulnerable")
    ]
    
    try:
        with socket.create_connection((target_ip, port), timeout=5) as s:
            for header, value in test_headers:
                request = f"GET /cgi-bin/test HTTP/1.1\r\nHost: {target_ip}\r\n{header}: {value}\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode())
                response = s.recv(4096).decode(errors='ignore')
                
                if 'vulnerable' in response:
                    return {"Vulnerable": True, "Type": "Shellshock", "CVE": "CVE-2014-6271", "Vector": header}
    except Exception:
        pass
    return None

@nse_script("http-robots-txt", category="discovery")
def script_http_robots_txt(target_ip, port, payload=None):
    """Parses robots.txt for hidden paths."""
    try:
        with socket.create_connection((target_ip, port), timeout=5) as s:
            request = f"GET /robots.txt HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(8192).decode(errors='ignore')
            
            if 'Disallow:' in response or 'Allow:' in response:
                # Extract disallowed paths
                disallowed = []
                for line in response.split('\n'):
                    if 'Disallow:' in line:
                        path = line.split('Disallow:')[1].strip()
                        if path and path != '/':
                            disallowed.append(path)
                return {"Disallowed": disallowed} if disallowed else {"Found": True}
    except Exception:
        pass
    return None

# ==============================================================================
# === DATABASE SCRIPTS =========================================================
# ==============================================================================

@nse_script("mysql-empty-password", category="vuln")
def script_mysql_empty_password(target_ip, port, payload=None):
    """Checks MySQL empty root password."""
    if port != 3306:
        return None
    
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=target_ip, port=port, user='root', password='', connect_timeout=3
        )
        conn.close()
        return {"Vulnerable": True, "Service": "MySQL", "Credentials": "root: (empty)", "Risk": "HIGH"}
    except ImportError:
        return {"Note": "mysql-connector-python not installed. Run: pip install mysql-connector-python"}
    except:
        pass
    return None

@nse_script("mysql-info", category="discovery")
def script_mysql_info(target_ip, port, payload=None):
    """Gathers MySQL information."""
    if port != 3306:
        return None
    
    try:
        import mysql.connector
        conn = mysql.connector.connect(host=target_ip, port=port, connect_timeout=3)
        info = {
            "Version": conn.get_server_info(),
            "Protocol": conn.get_server_protocol_version(),
            "Host": conn.get_server_host()
        }
        conn.close()
        return info
    except:
        pass
    return None

@nse_script("redis-info", category="discovery")
def script_redis_info(target_ip, port, payload=None):
    """Gathers Redis information (no auth required often)."""
    if port != 6379:
        return None
    
    try:
        with socket.create_connection((target_ip, port), timeout=3) as s:
            s.send(b"INFO\r\n")
            response = s.recv(8192).decode(errors='ignore')
            
            if 'redis_version' in response:
                info = {}
                for line in response.split('\n'):
                    if ':' in line and not line.startswith('#'):
                        key, val = line.split(':', 1)
                        info[key.strip()] = val.strip()
                return {"Redis Info": info}
    except Exception:
        pass
    return None

# ==============================================================================
# === SMB WINDOWS SCRIPTS ======================================================
# ==============================================================================

@nse_script("smb-enum-shares", category="discovery")
def script_smb_enum_shares(target_ip, port, payload=None):
    """Enumerates SMB shares."""
    if port != 445:
        return None
    
    common_shares = ['C$', 'ADMIN$', 'IPC$', 'print$', 'Share', 'Public', 'Documents']
    found_shares = []
    
    try:
        with socket.create_connection((target_ip, port), timeout=5) as s:
            for share in common_shares:
                # Simple SMB probe for share existence
                negotiate = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8'
                s.send(negotiate)
                s.recv(1024)
                
                # Try to list share
                s.send(b'\x00\x00\x00\x48\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x00\x00\x00')
                response = s.recv(1024)
                if len(response) > 0:
                    found_shares.append(share)
    except Exception:
        pass
    
    return {"Found Shares": found_shares} if found_shares else None

# ==============================================================================
# === CTF SPECIFIC SCRIPTS =====================================================
# ==============================================================================

@nse_script("ctf-flag-search", category="discovery")
def script_ctf_flag_search(target_ip, port, payload=None):
    """Searches for common CTF flag locations."""
    flag_paths = [
        '/flag', '/flag.txt', '/flag.php', '/flag.html', '/root/flag.txt',
        '/home/user/flag.txt', '/var/www/flag.txt', '/secret/flag',
        '/ctf/flag', '/challenge/flag', '/.flag', '/FLAG'
    ]
    
    found_flags = []
    
    try:
        with socket.create_connection((target_ip, port), timeout=5) as s:
            for path in flag_paths:
                request = f"GET {path} HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode())
                response = s.recv(4096).decode(errors='ignore')
                
                # Check for flag patterns
                flag_patterns = ['CTF{', 'flag{', 'FLAG{', 'ctf{']
                for pattern in flag_patterns:
                    if pattern in response:
                        # Extract flag
                        import re
                        match = re.search(f'{pattern}[^}}]*}}', response)
                        if match:
                            found_flags.append(match.group(0))
    except Exception:
        pass
    
    return {"Flags Found": found_flags} if found_flags else None

@nse_script("ctf-common-ports", category="discovery")
def script_ctf_common_ports(target_ip, port, payload=None):
    """Checks common CTF alternative ports."""
    ctf_ports = [1337, 31337, 8000, 8080, 8443, 8888, 9000, 9999, 12345, 31337]
    
    open_ports = []
    for ctf_port in ctf_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((target_ip, ctf_port)) == 0:
                    open_ports.append(ctf_port)
        except:
            pass
    
    return {"Open CTF Ports": open_ports} if open_ports else None

