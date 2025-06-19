import os
import json
import csv
from datetime import datetime
import nmap
from .utils import upload_to_artifactory
from .logging_config import setup_logging

class VulnerabilityScanner:
    def __init__(self, target, report_dir, artifactory_url, artifactory_user, artifactory_password):
        self.target = target
        self.report_dir = report_dir
        self.artifactory_url = artifactory_url
        self.artifactory_user = artifactory_user
        self.artifactory_password = artifactory_password
        self.logger = setup_logging()
        os.makedirs(self.report_dir, exist_ok=True)
        self.results = []

    def run_scan_and_report(self):
        """Run nmap vulnerability scan, generate reports, log to CSV, and upload to Artifactory."""
        self.logger.info(f"Starting vulnerability scan for {self.target}")
        scan_results = self.perform_scan()
        self.parse_scan_results(scan_results)
        json_report_path = self.generate_json_report()
        self.log_results_to_csv()
        if self.artifactory_url and self.artifactory_user and self.artifactory_password:
            self.upload_to_artifactory(json_report_path)

    def perform_scan(self):
        """Perform nmap vulnerability scan."""
        nm = nmap.PortScanner()
        self.logger.info(f"Running nmap scan with vuln scripts on {self.target}")
        try:
            # Use -sV for version detection, --script vuln for vulnerability scripts
            nm.scan(self.target, arguments="-sV --script vuln -p-")
            return nm
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error during scan: {e}")
            return None

    def parse_scan_results(self, nm):
        """Parse nmap scan results."""
        if not nm:
            self.logger.warning("No scan results to parse")
            return

        self.logger.info("Parsing scan results")
        for host in nm.all_hosts():
            host_results = {
                "host": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "ports": [],
                "vulnerabilities": []
            }
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_info = nm[host][proto][port]
                    port_result = {
                        "port": port,
                        "state": port_info["state"],
                        "service": port_info.get("name", "unknown"),
                        "version": port_info.get("version", "unknown")
                    }
                    # Check for vulnerability script output
                    if "script" in port_info:
                        for script_id, output in port_info["script"].items():
                            if "vuln" in script_id.lower():
                                host_results["vulnerabilities"].append({
                                    "script": script_id,
                                    "output": output.strip()
                                })
                    host_results["ports"].append(port_result)
            self.results.append(host_results)

    def generate_json_report(self):
        """Generate JSON report of scan results."""
        self.logger.info("Generating JSON report")
        report_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target,
            "results": self.results,
            "total_hosts": len(self.results),
            "total_open_ports": sum(len(r["ports"]) for r in self.results),
            "total_vulnerabilities": sum(len(r["vulnerabilities"]) for r in self.results)
        }
        json_path = os.path.join(self.report_dir, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(json_path, "w") as f:
                json.dump(report_data, f, indent=4)
            self.logger.info(f"JSON report saved to {json_path}")
            return json_path
        except Exception as e:
            self.logger.error(f"Failed to write JSON report: {e}")
            return None

    def log_results_to_csv(self):
        """Log scan results to CSV."""
        if not self.results:
            self.logger.warning("No results to log to CSV")
            return
        csv_path = os.path.join(self.report_dir, f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        self.logger.info(f"Logging results to {csv_path}")
        try:
            with open(csv_path, mode="w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["timestamp", "host", "port", "state", "service", "version", "vulnerability"])
                writer.writeheader()
                for result in self.results:
                    for port in result["ports"]:
                        row = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "host": result["host"],
                            "port": port["port"],
                            "state": port["state"],
                            "service": port["service"],
                            "version": port["version"],
                            "vulnerability": ""
                        }
                        for vuln in result["vulnerabilities"]:
                            row["vulnerability"] = f"{vuln['script']}: {vuln['output']}"
                            writer.writerow(row)
                        if not result["vulnerabilities"]:
                            writer.writerow(row)
        except Exception as e:
            self.logger.error(f"Failed to write CSV: {e}")

    def upload_to_artifactory(self, json_report_path):
        """Upload JSON report to Artifactory."""
        if not json_report_path:
            self.logger.warning("No JSON report to upload")
            return
        self.logger.info(f"Uploading {json_report_path} to Artifactory")
        try:
            upload_to_artifactory(
                json_report_path,
                self.artifactory_url,
                self.artifactory_user,
                self.artifactory_password
            )
        except Exception as e:
            self.logger.error(f"Failed to upload to Artifactory: {e}")