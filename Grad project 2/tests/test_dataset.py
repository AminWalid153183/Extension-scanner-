# tests/test_dataset.py
import os
import pandas as pd
import json
from pathlib import Path
from main import is_known_malicious

def test_is_known_malicious(tmp_path):
    # Create a fake dataset CSV
    dataset = pd.DataFrame({
        'EXTID': ['abcdabcdabcdabcd', '1234123412341234']
    })
    dataset_path = tmp_path / "your_dataset.csv"
    dataset.to_csv(dataset_path, index=False)

    # Set the environment variable to point to our fake dataset
    os.environ["MALICIOUS_DATASET_PATH"] = str(dataset_path)

    # Create a fake extension directory and manifest.json
    extension_dir = tmp_path / "abcdabcdabcdabcd" / "1.0.0"
    extension_dir.mkdir(parents=True)

    manifest_path = extension_dir.parent / "manifest.json"
    manifest_content = {
        "manifest_version": 2,
        "name": "Test Extension",
        "version": "1.0",
    }
    manifest_path.write_text(json.dumps(manifest_content))

    # Now test
    result = is_known_malicious(extension_dir)
    assert result is True, "Extension should be detected as malicious"

def test_is_not_malicious(tmp_path):
    # Create a fake dataset CSV
    dataset = pd.DataFrame({
        'EXTID': ['abcdabcdabcdabcd', '1234123412341234']
    })
    dataset_path = tmp_path / "your_dataset.csv"
    dataset.to_csv(dataset_path, index=False)

    os.environ["MALICIOUS_DATASET_PATH"] = str(dataset_path)

    # Create a different extension not in the dataset
    extension_dir = tmp_path / "otherextensionid" / "1.0.0"
    extension_dir.mkdir(parents=True)

    manifest_path = extension_dir.parent / "manifest.json"
    manifest_content = {
        "manifest_version": 2,
        "name": "Another Extension",
        "version": "1.0",
    }
    manifest_path.write_text(json.dumps(manifest_content))

    result = is_known_malicious(extension_dir)
    assert result is False, "Extension should not be detected as malicious"
