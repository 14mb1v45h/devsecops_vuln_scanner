import argparse
import os
from devsecops_vuln_scanner.scanner import VulnerabilityScanner
from devsecops_vuln_scanner.logging_config import setup_logging

def main():
    logger = setup_logging()
    parser = argparse.ArgumentParser(description="DevSecOps Vulnerability Scanner Automation Tool")
    parser.add_argument("--target", required=True, help="Target host or network (e.g., 192.168.1.0/24)")
    parser.add_argument("--report-dir", default="scan_reports", help="Output directory for JSON and CSV reports")
    parser.add_argument("--artifactory-url", help="Artifactory URL (e.g., https://myrepo.jfrog.io/artifactory)")
    args = parser.parse_args()

    logger.info("Starting DevSecOps Vulnerability Scanner")
    scanner = VulnerabilityScanner(
        target=args.target,
        report_dir=args.report_dir,
        artifactory_url=args.artifactory_url or os.getenv("ARTIFACTORY_URL"),
        artifactory_user=os.getenv("ARTIFACTORY_USER"),
        artifactory_password=os.getenv("ARTIFACTORY_PASSWORD")
    )
    scanner.run_scan_and_report()

if __name__ == "__main__":
    main()
