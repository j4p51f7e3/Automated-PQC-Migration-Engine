import json
import pytest

from scanner.models import SecurityFinding
from scanner.llm.models import SemanticPurpose, ConfidenceLevel
from scanner.llm.client import MockLLMClient
from scanner.llm.analyzer import LLMAnalyzer

@pytest.fixture
def dummy_finding():
    return SecurityFinding(
        rule_id="R1",
        file="test.py",
        line=10,
        column=0,
        algorithm="RSA",
        category="Cryptography",
        severity="HIGH",
        description="Found RSA",
        recommendation="Use PQC",
        detected_api="cryptography.hazmat.primitives.asymmetric.rsa",
        usage="Unknown",
        function_name="sign_data",
        source_context="private_key.sign(data)"
    )

def test_clear_signature(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Digital Signature",
        "confidence": "HIGH",
        "evidence": ["private_key.sign() called"],
        "reasoning": "Signing data",
        "manual_review_required": False
    })
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.DIGITAL_SIGNATURE
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.evidence == ["private_key.sign() called"]
    assert result.reasoning == "Signing data"
    assert result.manual_review_required is False

def test_clear_key_establishment(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Key Establishment",
        "confidence": "MEDIUM",
        "evidence": ["exchange() used"],
        "reasoning": "Key exchange",
        "manual_review_required": False
    })
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.KEY_ESTABLISHMENT
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.manual_review_required is False

def test_ambiguous_code(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Unknown",
        "confidence": "LOW",
        "evidence": [],
        "reasoning": "Not enough context",
        "manual_review_required": False
    })
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.UNKNOWN
    assert result.confidence == ConfidenceLevel.LOW
    assert result.manual_review_required is True

def test_malformed_json(dummy_finding):
    client = MockLLMClient()
    client.next_response = "I think it's a signature but here is no json."
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.UNKNOWN
    assert result.confidence == ConfidenceLevel.LOW
    assert result.manual_review_required is True

def test_invalid_purpose(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Blockchain",
        "confidence": "HIGH",
        "evidence": [],
        "reasoning": "",
        "manual_review_required": False
    })
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.UNKNOWN
    assert result.manual_review_required is True

def test_invalid_confidence(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Digital Signature",
        "confidence": "CERTAIN",
        "evidence": [],
        "reasoning": "",
        "manual_review_required": False
    })
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.UNKNOWN
    assert result.manual_review_required is True

def test_missing_keys(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "confidence": "HIGH",
        "evidence": [],
        "reasoning": "",
        "manual_review_required": False
    }) # missing purpose
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.UNKNOWN
    assert result.manual_review_required is True

def test_missing_evidence(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Digital Signature",
        "confidence": "HIGH",
        "reasoning": "Signing data",
        "manual_review_required": False
    }) # missing evidence
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.UNKNOWN
    assert result.manual_review_required is True

def test_missing_reasoning(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Digital Signature",
        "confidence": "HIGH",
        "evidence": ["test"],
        "manual_review_required": False
    }) # missing reasoning
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.UNKNOWN
    assert result.manual_review_required is True

def test_multiple_evidence_items(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Digital Signature",
        "confidence": "HIGH",
        "evidence": ["Item 1", "Item 2"],
        "reasoning": "Signing data",
        "manual_review_required": False
    })
    analyzer = LLMAnalyzer(client)
    
    result = analyzer.analyze_finding(dummy_finding)
    assert result.evidence == ["Item 1", "Item 2"]

def test_regression_mock_behavior_dynamic():
    # Test that different findings can be handled correctly when the LLM responds with different data
    client = MockLLMClient()
    analyzer = LLMAnalyzer(client)
    
    # 1. RSA Key gen only
    f1 = SecurityFinding(rule_id="R1", file="f1.py", line=1, column=0, algorithm="RSA", category="Crypto", severity="HIGH", description="", recommendation="", detected_api="rsa.generate_private_key", usage="Key Generation", source_context="rsa.generate_private_key()")
    client.next_response = json.dumps({
        "purpose": "Unknown",
        "confidence": "LOW",
        "evidence": ["Only key generation is visible in context"],
        "reasoning": "Key generation alone does not reveal whether the key is used for signatures, encryption, or key establishment.",
        "manual_review_required": True
    })
    r1 = analyzer.analyze_finding(f1)
    assert r1.purpose == SemanticPurpose.UNKNOWN
    assert r1.manual_review_required is True
    
    # 2. RSA Digital signature
    f2 = SecurityFinding(rule_id="R2", file="f2.py", line=1, column=0, algorithm="RSA", category="Crypto", severity="HIGH", description="", recommendation="", detected_api="rsa", usage="Digital Signature", source_context="private_key.sign(data)")
    client.next_response = json.dumps({
        "purpose": "Digital Signature",
        "confidence": "HIGH",
        "evidence": ["sign() is called in the source context"],
        "reasoning": "The explicit call to sign() indicates digital signature generation.",
        "manual_review_required": False
    })
    r2 = analyzer.analyze_finding(f2)
    assert r2.purpose == SemanticPurpose.DIGITAL_SIGNATURE
    assert r2.manual_review_required is False
    
    # 3. MD5 Hash
    f3 = SecurityFinding(rule_id="R3", file="f3.py", line=1, column=0, algorithm="MD5", category="Hash", severity="HIGH", description="", recommendation="", detected_api="hashlib.md5", usage="Hashing", source_context="hashlib.md5(data)")
    client.next_response = json.dumps({
        "purpose": "Hashing",
        "confidence": "HIGH",
        "evidence": ["Hashing function called"],
        "reasoning": "This is a hashing operation, not a digital signature or encryption.",
        "manual_review_required": False
    })
    r3 = analyzer.analyze_finding(f3)
    assert r3.purpose == SemanticPurpose.HASHING
    assert r3.manual_review_required is False
    
    # 4. ECC Key Agreement
    f4 = SecurityFinding(rule_id="R4", file="f4.py", line=1, column=0, algorithm="ECC", category="Crypto", severity="HIGH", description="", recommendation="", detected_api="ecc", usage="Key Generation", source_context="private_key.exchange(peer)")
    client.next_response = json.dumps({
        "purpose": "Key Agreement",
        "confidence": "HIGH",
        "evidence": ["exchange() is called in the source context"],
        "reasoning": "The context shows key agreement operations.",
        "manual_review_required": False
    })
    r4 = analyzer.analyze_finding(f4)
    assert r4.purpose == SemanticPurpose.KEY_AGREEMENT
    assert r4.manual_review_required is False

    # 5. RSA Key Establishment
    f5 = SecurityFinding(rule_id="R5", file="f5.py", line=1, column=0, algorithm="RSA", category="Crypto", severity="HIGH", description="", recommendation="", detected_api="rsa", usage="Key Generation", source_context="public_key.encrypt(shared_key)")
    client.next_response = json.dumps({
        "purpose": "Key Establishment",
        "confidence": "HIGH",
        "evidence": ["encrypt() is called on an RSA key"],
        "reasoning": "Explicit RSA encryption call indicating key transport.",
        "manual_review_required": False
    })
    r5 = analyzer.analyze_finding(f5)
    assert r5.purpose == SemanticPurpose.KEY_ESTABLISHMENT
    assert r5.manual_review_required is False

def test_low_confidence_forces_manual_review(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Digital Signature",
        "confidence": "LOW",
        "evidence": ["Looks like a signature"],
        "reasoning": "Might be signing",
        "manual_review_required": False
    })
    analyzer = LLMAnalyzer(client)
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.DIGITAL_SIGNATURE
    assert result.confidence == ConfidenceLevel.LOW
    assert result.manual_review_required is True

def test_unknown_purpose_forces_manual_review(dummy_finding):
    client = MockLLMClient()
    client.next_response = json.dumps({
        "purpose": "Unknown",
        "confidence": "HIGH",
        "evidence": ["No idea"],
        "reasoning": "Very confident I have no idea",
        "manual_review_required": False
    })
    analyzer = LLMAnalyzer(client)
    result = analyzer.analyze_finding(dummy_finding)
    assert result.purpose == SemanticPurpose.UNKNOWN
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.manual_review_required is True
