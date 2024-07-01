import re
import idna
from urllib.parse import urlparse, urlunparse, unquote
import ipaddress

def canonicalize_hostname(hostname):
    # Check if the hostname is an IPv6 address (enclosed in square brackets)
    if hostname.startswith('[') and hostname.endswith(']'):
        # Remove the square brackets for parsing
        ipv6 = hostname[1:-1]
        try:
            ipv6_addr = ipaddress.IPv6Address(ipv6)
            if ipv6_addr.ipv4_mapped:
                # If it's an IPv4-mapped IPv6 address, transform to IPv4
                hostname = str(ipv6_addr.ipv4_mapped)
            elif ipv6_addr.sixtofour:
                # If it's a NAT64 address, transform to IPv4
                hostname = str(ipv6_addr.sixtofour)
            else:
                # Otherwise, use the compressed form of IPv6 address
                hostname = f"[{ipv6_addr.compressed}]"
        except ipaddress.AddressValueError:
            pass
    else:
        # Remove port if present
        if ':' in hostname:
            hostname, port = hostname.rsplit(':', 1)
        else:
            port = None
        
        # Remove leading and trailing dots
        hostname = hostname.strip('.')
        
        # Replace consecutive dots with a single dot
        hostname = re.sub(r'\.+', '.', hostname)
        
        try:
            # Try to parse as IPv4 address
            ipv4 = ipaddress.IPv4Address(hostname)
            hostname = str(ipv4)
        except ipaddress.AddressValueError:
            # If it's not an IP address, encode to ASCII Punycode
            hostname = idna.encode(hostname).decode('ascii')
        
        # Convert to lowercase
        hostname = hostname.lower()
        
        # Add port back if present
        if port:
            hostname = f"{hostname}:{port}"
    
    return hostname

def canonicalize_url(url):
    # Remove tab, CR and LF characters
    url = url.replace('\t', '').replace('\r', '').replace('\n', '')
    
    # Parse URL components
    parsed_url = urlparse(url)
    
    # Canonicalize the hostname
    netloc = canonicalize_hostname(parsed_url.netloc)
    
    # Remove fragment
    path = parsed_url.path.rstrip('/')
    
    # If path is empty, set it to '/'
    if not path:
        path = '/'
    
    # Keep query string as is
    query = parsed_url.query
    
    # Construct the canonical URL
    canonical_url = urlunparse((parsed_url.scheme, netloc, path, '', query, ''))
    
    # Repeatedly percent-unescape the URL
    previous_url = ''
    while previous_url != canonical_url:
        previous_url = canonical_url
        canonical_url = unquote(canonical_url)
    
    return canonical_url

# Example usage
urls = [
    "http://example.com",
    "https://example.com/",
    "http://www.example.com",
    "http://example.com/index.html#section",
    "http://example.com/index.html?",
    "http://example.com/index.html?utm_source=google",
    "http://xn--fsq.com/",  # internationalized domain name
    "http://example.com/%7Eusername/",
    "http://EXAMPLE.com/../a/b/../c/./d.html",
    "http://example.com:80/",
    "http://EXAMPLE.COM./",
    "http://user:pass@EXAMPLE.COM/",
    "http://127.0.0.1",
    "http://0177.1",
    "http://0x7f.1",
    "http://[2001:db8::1]",
    "http://[::ffff:192.168.1.1]",
    "http://[64:ff9b::192.168.1.1]",
    "http://[2001:0db8:0000:0000:0000:ff00:0042:8329]",
]

for url in urls:
    print(f"Original URL: {url}")
    print(f"Canonical URL: {canonicalize_url(url)}\n")
