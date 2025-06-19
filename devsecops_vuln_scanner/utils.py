from artifactory import ArtifactoryPath
import os

def upload_to_artifactory(file_path, artifactory_url, username, password):
    """Upload a file to Artifactory."""
    path = ArtifactoryPath(
        f"{artifactory_url.rstrip('/')}/{os.path.basename(file_path)}",
        auth=(username, password)
    )
    with open(file_path, "rb") as f:
        path.write(f)