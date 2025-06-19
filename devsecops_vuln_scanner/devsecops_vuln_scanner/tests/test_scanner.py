import pytest
import os
from unittest.mock import patch, MagicMock
from devsecops_vuln_scanner.scanner import VulnerabilityScanner

@pytest.fixture
def scanner(tmp_path):
    report_dir = tmp_path / "scan_reports"
    return VulnerabilityScanner(
        target="192.168.1.1",
        report_dir=str(report_dir),
        artifactory_url=None,
        artifactory_user=None,
        artifactory_password=None
    )

class TestVulnerabilityScanner:
    @patch("devsecops_vuln_scanner.scanner.nmap.PortScanner")
    def test_perform_scan_success(self, mock_nmap, scanner):
        mock_scanner = MagicMock()
        mock_nmap.return_value = mock_scanner
        result = scanner.perform_scan()
        assert result == mock_scanner
        mock_scanner.scan.assert_called_once_with("192.168.1.1", arguments="-sV --script vuln -p-")

    @patch("devsecops_vuln_scanner.scanner.nmap.PortScanner")
    def test_perform_scan_failure(self, mock_nmap, scanner):
        mock_nmap.return_value.scan.side_effect = nmap.PortScannerError("Scan error")
        result = scanner.perform_scan()
        assert result is None

    @patch("devsecops_vuln_scanner.scanner.nmap.PortScanner")
    def test_parse_scan_results(self, mock_nmap, scanner):
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ["192.168.1.1"]
        mock_scanner.__getitem__.return_value.hostname.return_value = "test-host"
        mock_scanner.__getitem__.return_value.state.return_value = "up"
        mock_scanner.__getitem__.return_value.all_protocols.return_value = ["tcp"]
        mock_scanner.__getitem__.return_value.__getitem__.return_value.keys.return_value = [80]
        mock_scanner.__getitem__.return_value.__getitem__.return_value.__getitem__.return_value = {
            "state": "open",
            "name": "http",
            "version": "Apache 2.4",
            "script": {"vuln-http": "Vulnerable to XSS"}
        }
        scanner.parse_scan_results(mock_scanner)
        assert len(scanner.results) == 1
        assert scanner.results[0]["host"] == "192.168.1.1"
        assert len(scanner.results[0]["ports"]) == 1
        assert len(scanner.results[0]["vulnerabilities"]) == 1

    def test_generate_json_report(self, scanner):
        scanner.results = [{
            "host": "192.168.1.1",
            "hostname": "test-host",
            "state": "up",
            "ports": [{"port": 80, "state": "open", "service": "http", "version": "Apache 2.4"}],
            "vulnerabilities": [{"script": "vuln-http", "output": "Vulnerable to XSS"}]
        }]
        json_path = scanner.generate_json_report()
        assert os.path.exists(json_path)
        with open(json_path, "r") as f:
            data = json.load(f)
            assert data["target"] == "192.168.1.1"
            assert data["total_open_ports"] == 1
            assert data["total_vulnerabilities"] == 1

    def test_log_results_to_csv(self, scanner):
        scanner.results = [{
            "host": "192.168.1.1",
            "hostname": "test-host",
            "state": "up",
            "ports": [{"port": 80, "state": "open", "service": "http", "version": "Apache 2.4"}],
            "vulnerabilities": [{"script": "vuln-http", "output": "Vulnerable to XSS"}]
        }]
        scanner.log_results_to_csv()
        csv_files = [f for f in os.listdir(scanner.report_dir) if f.endswith(".csv")]
        assert len(csv_files) == 1
        with open(os.path.join(scanner.report_dir, csv_files[0]), "r") as f:
            content = f.read()
            assert "192.168.1.1" in content
            assert "vuln-http" in content