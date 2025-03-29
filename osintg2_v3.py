import os
import requests
import socket
import dns.resolver
from ipwhois import IPWhois
from termcolor import colored
from googlesearch import search
import ssl
import OpenSSL
import re
import time
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def is_ip(target):
    """Check if the target is an IP address."""
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(ip_pattern, target))

# ✅ IP Geolocation Lookup
def get_ip_location(ip):
    print(colored("\n[IP Geolocation Lookup]", "cyan"))
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        country = result.get("asn_country_code", "Unknown")
        asn = result.get("asn_description", "Unknown")
        print(colored(f"IP: {ip}", "green"))
        print(colored(f"Country: {country}", "green"))
        print(colored(f"ASN: {asn}", "green"))
    except Exception as e:
        print(colored(f"[ERROR] Could not fetch IP location: {e}", "red"))

def create_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

# ✅ Subdomain Finder
def get_subdomains(domain):
    print(colored("\n[Subdomains Found]", "cyan"))
    subdomains = ["mail", "admin", "blog", "vpn", "api"]
    found = False
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            print(colored(f"{subdomain} --> {ip}", "green"))
            found = True
        except socket.gaierror:
            pass
    if not found:
        print(colored("[ERROR] No subdomains found!", "red"))

# ✅ SSL Security Check
def check_ssl(domain):
    print(colored("\n[SSL Security Check]", "cyan"))
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        issuer = x509.get_issuer().get_components()
        valid_until = x509.get_notAfter().decode()

        print(colored(f"Issuer: {issuer}", "green"))
        print(colored(f"Valid Until: {valid_until}", "green"))

    except Exception as e:
        print(colored(f"[ERROR] SSL check failed: {e}", "red"))

# ✅ Admin Panel Finder
def find_admin_panels(domain):
    print(colored("\n[Admin Panel Finder]", "cyan"))
    admin_paths = ["/admin", "/wp-admin", "/dashboard", "/login"]
    found = False
    for path in admin_paths:
        url = f"https://{domain}{path}"
        try:
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                print(colored(f"Found: {url}", "green"))
                found = True
        except requests.exceptions.RequestException:
            pass
    if not found:
        print(colored("[ERROR] No admin panels found!", "red"))

# ✅ Google Dorking with Random Delays & User-Agent Rotation
def google_dorking(domain):
    print(colored("\n[Google Dorking Results]", "cyan"))
    
    dorks = [
        f"site:{domain} intitle:index.of",
        f"site:{domain} inurl:admin",
        f"site:{domain} filetype:pdf",
    ]
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    ]
    
    found = False
    
    for dork in dorks:
        print(colored(f"\nDork: {dork}", "yellow"))
        headers = {"User-Agent": random.choice(user_agents)}  # Randomize User-Agent
        
        try:
            for result in search(dork, num_results=3, headers=headers):
                print(colored(result, "green"))
                found = True
            time.sleep(random.randint(15, 30))  # Random delay to avoid rate limiting
            
        except Exception as e:
            print(colored(f"[ERROR] Google blocked requests (Status: 429), switching to Bing!", "red"))
            bing_dorking(domain)  # Fallback to Bing
            return
    
    if not found:
        print(colored("[ERROR] No results found on Google!", "red"))

# ✅ Bing Dorking (Fallback)
def bing_dorking(domain):
    print(colored("\n[Bing Dorking Results]", "cyan"))
    
    dorks = [
        f"site:{domain} intitle:index.of",
        f"site:{domain} inurl:admin",
        f"site:{domain} filetype:pdf",
    ]
    
    for dork in dorks:
        url = f"https://www.bing.com/search?q={dork}"
        print(colored(f"Search Bing: {url}", "green"))

# ✅ Directory Bruteforce
def directory_bruteforce(domain):
    print(colored("\n[Directory Bruteforce]", "cyan"))
    directories = ["backup", "db", "test", "uploads", "admin"]
    found = False
    for dir in directories:
        url = f"https://{domain}/{dir}/"
        try:
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                print(colored(f"Found: {url}", "green"))
                found = True
        except requests.exceptions.RequestException:
            pass
    if not found:
        print(colored("[ERROR] No directories found!", "red"))

# ✅ DNS Record Extraction
def get_dns_records(domain):
    print(colored("\n[DNS Records]", "cyan"))
    record_types = ["A", "MX", "TXT", "NS"]
    found = False
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                print(colored(f"{record} Record: {rdata}", "green"))
                found = True
        except dns.resolver.NoAnswer:
            pass
    if not found:
        print(colored("[ERROR] No DNS records found!", "red"))

# ✅ Port Scanner
def scan_ports(target):
    print(colored("\n[Port Scan]", "cyan"))
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Proxy"
    }
    open_ports = []
    for port in common_ports.keys():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
    if open_ports:
        print(colored("Open Ports:", "green"))
        for port in open_ports:
            print(colored(f"{port} ({common_ports[port]})", "green"))
    else:
        print(colored("[ERROR] No open ports found!", "red"))
# ✅ ASN Lookup
def get_asn_info(ip):
    print(colored("\n[ASN Lookup]", "cyan"))
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        asn = result.get("asn", "Unknown")
        isp = result.get("asn_description", "Unknown")
        print(colored(f"ASN: {asn}", "green"))
        print(colored(f"ISP: {isp}", "green"))
    except Exception as e:
        print(colored(f"[ERROR] Could not fetch ASN info: {e}", "red"))

# ✅ Identify Open Redirects
def identify_open_redirects(domain):
    print(colored("\n[Open Redirect Check]", "cyan"))
    test_urls = [
        f"https://{domain}/redirect?url=http://evil.com",
        f"https://{domain}/out?url=http://evil.com",
        f"https://{domain}/go?url=http://evil.com",
    ]
    found = False
    for url in test_urls:
        try:
            response = requests.get(url, allow_redirects=True, timeout=3)
            if "evil.com" in response.url:
                print(colored(f"Possible Open Redirect: {url}", "yellow"))
                found = True
        except requests.exceptions.RequestException:
            pass
    if not found:
        print(colored("[INFO] No open redirects found!", "green"))

# ✅ Find Embedded Social Media Links
def find_social_links(domain):
    print(colored("\n[Social Media Links Found]", "cyan"))
    social_patterns = {
        "Facebook": r"facebook\.com/[a-zA-Z0-9_.-]+",
        "Twitter": r"twitter\.com/[a-zA-Z0-9_.-]+",
        "LinkedIn": r"linkedin\.com/in/[a-zA-Z0-9_-]+",
        "Instagram": r"instagram\.com/[a-zA-Z0-9_.-]+"
    }
    try:
        response = requests.get(f"https://{domain}", timeout=3)
        found = False
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, response.text)
            for match in set(matches):
                print(colored(f"{platform}: https://{match}", "green"))
                found = True
        if not found:
            print(colored("[INFO] No embedded social media links found!", "green"))
    except requests.exceptions.RequestException:
        print(colored("[ERROR] Could not fetch website content!", "red"))

# ✅ Check if Site Uses Cloudflare or Other Protection
def check_protection(domain):
    print(colored("\n[Cloudflare & WAF Detection]", "cyan"))
    
    waf_signatures = {
        "Cloudflare": ["cloudflare"],
        "AWS CloudFront": ["cloudfront", "x-amz-cf-id", "x-amzn-requestid"],
        "Akamai": ["akamai"],
        "Sucuri": ["sucuri"],
        "Imperva (Incapsula)": ["incapsula"],
        "Google Cloud Armor": ["gws"],
        "Fastly": ["fastly"],
        "StackPath": ["stackpath"],
        "Azure (Microsoft)": ["x-ms"],
        "F5 Networks (BIG-IP)": ["bigip"],
        "Barracuda": ["barracuda"],
        "Citrix NetScaler": ["netscaler"],
        "Alibaba Cloud CDN": ["aliyun"],
        "DDoS-Guard": ["ddos-guard"],
        "BlazingFast": ["blazingfast"],
        "KeyCDN": ["keycdn"],
        "Reblaze": ["reblaze"],
        "Edgecast (Verizon)": ["ecd"],
        "CDN77": ["cdn77"],
        "Yunjiasu (Baidu)": ["yunjiasu"],
        "CacheFly": ["cachefly"]
    }

    try:
        session = requests.Session()
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        
        response = session.get(f"https://{domain}", timeout=5)
        headers = response.headers

        for waf, signatures in waf_signatures.items():
            for signature in signatures:
                if any(signature in str(value).lower() for value in headers.values()):
                    print(colored(f"{waf} Detected!", "yellow"))
                    return

        # Google Frontend Detection (for YouTube and other Google services)
        if "server" in headers and "esf" in headers["server"].lower():
            print(colored("Google Frontend (GFE) Detected!", "yellow"))
            return

        # DNS lookup for AWS and Google IP range detection
        try:
            ip_address = socket.gethostbyname(domain)
            
            aws_ip_pattern = re.compile(r"^(3|13|18|52)\.(\d+)\.(\d+)\.(\d+)")
            if aws_ip_pattern.match(ip_address):
                print(colored("AWS Hosting Detected (via IP Range)", "yellow"))
                return

            google_ip_pattern = re.compile(r"^(64|66|142|216)\.(\d+)\.(\d+)\.(\d+)")
            if google_ip_pattern.match(ip_address):
                print(colored("Google Hosting Detected (via IP Range)", "yellow"))
                return

        except Exception:
            pass

        print(colored("No major protection detected.", "green"))

    except requests.RequestException as e:
        print(colored(f"[ERROR] Could not check WAF/CDN protection! {e}", "red"))

# ✅ Extract Email Addresses from Page Source
def extract_emails(domain):
    print(colored("\n[Extracting Email Addresses]", "cyan"))
    try:
        response = requests.get(f"https://{domain}", timeout=3)
        emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response.text))
        if emails:
            for email in emails:
                print(colored(email, "green"))
        else:
            print(colored("[INFO] No email addresses found!", "green"))
    except requests.exceptions.RequestException:
        print(colored("[ERROR] Could not fetch website content!", "red"))
# ✅ Detect Technologies Used on a Website
def detect_technologies(domain):
    print(colored("\n[Technology Detection]", "cyan"))

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }

    technologies = {
        "WordPress": "wp-content",
        "jQuery": "jquery.js",
        "Bootstrap": "bootstrap.css",
        "Django": "csrftoken",
        "Flask": "flask-session",
        "React": "react.js",
        "Angular": "angular.js"
    }

    try:
        session = create_session()
        response = session.get(f"https://{domain}", headers=headers, timeout=5)

        found_tech = [tech for tech, marker in technologies.items() if marker in response.text]
        if found_tech:
            print(colored(f"Detected Technologies: {', '.join(found_tech)}", "green"))
        else:
            print(colored("No common technologies detected.", "red"))

    except requests.RequestException as e:
        print(colored(f"[ERROR] Could not check technologies: {e}", "red"))

# ✅ Check If a Site is on a Blacklist
def check_blacklist(domain):
    print(colored("\n[Blacklist Check]", "cyan"))

    # List of well-known safe domains to prevent false positives
    whitelist = [
        "google.com", "microsoft.com", "apple.com", "github.com", "facebook.com",
        "amazon.com", "cloudflare.com", "wikipedia.org", "youtube.com"
    ]

    if domain in whitelist:
        print(colored(f"[SAFE] {domain} is a well-known site and is NOT blacklisted.", "green"))
        return

    blacklists = {
        "Google Safe Browsing": f"https://transparencyreport.google.com/safe-browsing/search?url={domain}",
        "OpenPhish": "https://openphish.com/feed.txt",
        "PhishTank": "https://www.phishtank.com/phish_search.php?valid=y&search={domain}",
        "Spamhaus": f"https://check.spamhaus.org/listed/?searchterm={domain}"
    }

    flagged = False

    # ✅ Check OpenPhish (without downloading full feed)
    try:
        openphish_data = requests.get(blacklists["OpenPhish"]).text
        if domain in openphish_data:
            print(colored(f"[ALERT] {domain} is listed in OpenPhish!", "red"))
            flagged = True
    except requests.exceptions.RequestException:
        print(colored("[ERROR] Could not check OpenPhish", "yellow"))

    # ✅ Check Google Safe Browsing (User must manually verify)
    print(colored(f"[INFO] Check manually on Google Safe Browsing: {blacklists['Google Safe Browsing']}", "yellow"))

    # ✅ Check PhishTank (User must manually verify)
    print(colored(f"[INFO] Check manually on PhishTank: {blacklists['PhishTank']}", "yellow"))

    # ✅ Check Spamhaus (User must manually verify)
    print(colored(f"[INFO] Check manually on Spamhaus: {blacklists['Spamhaus']}", "yellow"))

    if not flagged:
        print(colored(f"[SAFE] {domain} is NOT blacklisted!", "green"))


# ✅ Main Function Update
def main():
    target = input(colored("Enter a domain or IP: ", "blue")).strip()

    if is_ip(target):
        get_ip_location(target) # IP Geolocation
        get_asn_info(target)    # ASN Lookup
    else:
        get_subdomains(target)  # Subdomain Finder
        check_ssl(target)       # SSL Security Check
        find_admin_panels(target)   # Admin Panel Finder
        google_dorking(target)      # Google Dorking
        directory_bruteforce(target)    # Directory Bruteforce
        get_dns_records(target)         # DNS Record Extraction
        identify_open_redirects(target) # Open Redirect Detection
        find_social_links(target)    # Social Media Links Extraction
        check_protection(target)     # Cloudflare & WAF Detection
        extract_emails(target)      # Email Extraction
        detect_technologies(target)  # Technology Detection
        check_blacklist(target)   # Blacklist Check

    scan_ports(target)  # Port Scanner

if __name__ == "__main__":
    main()