import pytest
from unittest.mock import patch, MagicMock
from devsecops_vuln_scanner.utils import upload_to_artifactory

class TestUtils:
    @patch("devsecops_vuln_scanner.utils.ArtifactoryPath")
    def test_upload_to_artifactory_success(self, mock_artifactory, tmp_path):
        json_path = tmp_path / "report.json"
        json_path.write_text('{"test": "data"}')
        mock_path = MagicMock()
        mock_artifactory.return_value = mock_path
        upload_to_artifactory(
            file_path=str(json_path),
            artifactory_url="https://myrepo.jfrog.io/artifactory",
            username="user",
            password="password"
        )
        mock_artifactory.assert_called_once()
        mock_path.write.assert_called_once()