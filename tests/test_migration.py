import pytest
from scanner.models import SecurityFinding
from scanner.migration.analyzer import MigrationAnalyzer

def create_finding(algorithm: str, usage: str) -> SecurityFinding:
    return SecurityFinding(
        rule_id="TEST-001",
        file="test.py",
        line=1,
        column=1,
        algorithm=algorithm,
        category="Test Category",
        severity="HIGH",
        description="Test description",
        recommendation="Test recommendation",
        detected_api="test_api",
        usage=usage
    )

def test_rsa_key_establishment():
    finding = create_finding("RSA", "Key Establishment")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement == "ML-KEM"
    assert result.manual_review_required is False

def test_rsa_digital_signature():
    finding = create_finding("RSA", "Digital Signature")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement == "ML-DSA"
    assert "SLH-DSA" in result.alternative_replacements
    assert result.manual_review_required is False

def test_rsa_key_generation():
    finding = create_finding("RSA", "Key Generation")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement is None
    assert result.manual_review_required is True
    assert "ML-KEM" in result.alternative_replacements
    assert "ML-DSA" in result.alternative_replacements
    assert "SLH-DSA" in result.alternative_replacements

def test_rsa_unknown():
    finding = create_finding("RSA", "Unknown")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement is None
    assert result.manual_review_required is True

def test_ecc_key_agreement():
    finding = create_finding("ECC", "Key Agreement")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement == "ML-KEM"
    assert result.manual_review_required is False

def test_ecc_digital_signature():
    finding = create_finding("ECC", "Digital Signature")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement == "ML-DSA"
    assert result.manual_review_required is False

def test_ecc_key_generation():
    finding = create_finding("ECC", "Key Generation")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement is None
    assert result.manual_review_required is True

def test_ecc_unknown():
    finding = create_finding("ECC", "Unknown")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement is None
    assert result.manual_review_required is True

def test_md5_hashing():
    finding = create_finding("MD5", "Hashing")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement == "SHA-256"
    assert "SHA-3" in result.alternative_replacements
    assert result.manual_review_required is False

def test_sha1_hashing():
    finding = create_finding("SHA-1", "Hashing")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    assert result.primary_replacement == "SHA-256"
    assert "SHA-3" in result.alternative_replacements
    assert result.manual_review_required is False

def test_unsupported_algorithm():
    finding = create_finding("UNSUPPORTED", "Encryption")
    result = MigrationAnalyzer.analyze(finding)
    assert result is None

def test_migration_result_to_dict():
    finding = create_finding("RSA", "Key Establishment")
    result = MigrationAnalyzer.analyze(finding)
    assert result is not None
    result_dict = result.to_dict()
    assert isinstance(result_dict, dict)
    assert result_dict["algorithm"] == "RSA"
    assert result_dict["original_usage"] == "Key Establishment"
    assert result_dict["migration_type"] == "PQC Migration"
    assert result_dict["primary_replacement"] == "ML-KEM"
    assert "alternative_replacements" in result_dict
    assert result_dict["manual_review_required"] is False
    assert "reason" in result_dict
