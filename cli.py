"""
NOA SQL Scanner - Command Line Interface
Main entry point for the scanner
"""

import argparse
import sys
from crawler import Crawler
from scanner import SQLScanner
from reporter import Reporter
from config import BANNER, Colors, MAX_URLS

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='NOA SQL Scanner - Automated web security testing tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py -u https://example.com
  python cli.py -u https://example.com --deep --subdomains
  python cli.py -u https://example.com -o report.txt
  python cli.py -u https://example.com --threads 5

⚠️  WARNING: Use only on authorized targets!

Created by Nüvit Onur Altaş
        """
    )
    
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to scan (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '--deep',
        action='store_true',
        help='Enable deep crawling (up to max URLs)'
    )
    
    parser.add_argument(
        '--subdomains',
        action='store_true',
        help='Enable subdomain discovery and scanning'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='sqli_report.txt',
        help='Output file for report (default: sqli_report.txt)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=1,
        help='Number of threads (not implemented yet, reserved for future)'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Disable banner display'
    )
    
    return parser.parse_args()

def validate_url(url):
    """Validate target URL"""
    if not url.startswith(('http://', 'https://')):
        print(f"{Colors.FAIL}[-] Error: URL must start with http:// or https://{Colors.ENDC}")
        sys.exit(1)
    
    # Warn if using http instead of https
    if url.startswith('http://') and not url.startswith('https://'):
        print(f"{Colors.WARNING}[!] Warning: Using HTTP instead of HTTPS{Colors.ENDC}")

def main():
    """Main function"""
    args = parse_arguments()
    
    # Display banner
    if not args.no_banner:
        print(BANNER)
    
    # Validate URL
    validate_url(args.url)
    
    print(f"{Colors.OKBLUE}[*] Target: {args.url}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Subdomain Discovery: {'Enabled' if args.subdomains else 'Disabled'}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Deep Crawling: {'Enabled' if args.deep else 'Disabled'}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Max URLs: {MAX_URLS}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Output File: {args.output}{Colors.ENDC}\n")
    
    # User confirmation
    try:
        confirm = input(f"{Colors.WARNING}[!] Do you have permission to test this target? (yes/no): {Colors.ENDC}")
        if confirm.lower() != 'yes':
            print(f"{Colors.FAIL}[-] Scan aborted. Always obtain proper authorization before testing.{Colors.ENDC}")
            sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}[-] Scan aborted by user{Colors.ENDC}")
        sys.exit(0)
    
    print(f"\n{Colors.OKGREEN}[+] Starting scan...{Colors.ENDC}\n")
    
    try:
        # Initialize crawler
        crawler = Crawler(args.url)
        
        # Collect URLs to scan
        urls_to_scan = []
        
        if args.subdomains:
            # Full discovery mode (subdomains + crawling)
            print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
            print(f"{Colors.HEADER}PHASE 1: SUBDOMAIN DISCOVERY{Colors.ENDC}")
            print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
            
            urls_to_scan = crawler.run_full_discovery()
        else:
            # Simple crawl mode (no subdomain discovery)
            print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
            print(f"{Colors.HEADER}PHASE 1: URL DISCOVERY{Colors.ENDC}")
            print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
            
            urls_to_scan = crawler.crawl(args.url)
        
        if not urls_to_scan:
            print(f"{Colors.WARNING}[-] No URLs with parameters found to test{Colors.ENDC}")
            print(f"{Colors.WARNING}[-] Try enabling --deep or --subdomains flags{Colors.ENDC}")
            sys.exit(0)
        
        # SQL Injection Scanning
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}PHASE 2: SQL INJECTION TESTING{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        scanner = SQLScanner()
        vulnerabilities = scanner.scan_multiple_urls(urls_to_scan)
        
        # Generate Report
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}PHASE 3: REPORT GENERATION{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        reporter = Reporter(args.url)
        reporter.generate_txt_report(vulnerabilities, args.output)
        reporter.print_summary(vulnerabilities, len(urls_to_scan))
        
        # Exit with appropriate code
        if vulnerabilities:
            sys.exit(1)  # Vulnerabilities found
        else:
            sys.exit(0)  # No vulnerabilities
        
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}[-] Scan interrupted by user{Colors.ENDC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.FAIL}[-] Fatal error: {str(e)}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
