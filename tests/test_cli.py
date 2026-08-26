import os
import json
import subprocess
import pytest

MAIN_SCRIPT = "main.py"
TARGET_DIR = "test_repository"

def run_cli(*args):
    cmd = ["python", MAIN_SCRIPT] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result

def test_cli_basic_scan():
    result = run_cli(TARGET_DIR)
    assert result.returncode == 0
    assert "SCAN COMPLETE" in result.stdout
    assert "Files scanned" in result.stdout
    assert "Migration:" not in result.stdout

def test_cli_migration():
    result = run_cli(TARGET_DIR, "--migration")
    assert result.returncode == 0
    assert "Migration:" in result.stdout
    assert "SCAN COMPLETE" in result.stdout

def test_cli_format_json():
    result = run_cli(TARGET_DIR, "--format", "json")
    assert result.returncode == 0
    # Should be valid JSON
    data = json.loads(result.stdout)
    assert "findings" in data
    assert "migration" not in data["findings"][0]

def test_cli_migration_format_json():
    result = run_cli(TARGET_DIR, "--migration", "--format", "json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "findings" in data
    # At least one finding should have migration data if there are findings
    if data["findings"]:
        assert "migration" in data["findings"][0]

def test_cli_output_file(tmp_path):
    output_file = tmp_path / "report.json"
    result = run_cli(TARGET_DIR, "--migration", "--format", "json", "--output", str(output_file))
    assert result.returncode == 0
    # Output file should contain JSON
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert "findings" in data

def test_cli_invalid_format():
    result = run_cli(TARGET_DIR, "--format", "xml")
    assert result.returncode != 0
    assert "invalid choice: 'xml'" in result.stderr

def test_cli_invalid_target():
    result = run_cli("nonexistent_directory")
    assert result.returncode != 0
    assert "does not exist" in result.stderr

