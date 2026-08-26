from dataclasses import dataclass
from enum import Enum

class SemanticPurpose(Enum):
    KEY_ESTABLISHMENT = "Key Establishment"
    KEY_AGREEMENT = "Key Agreement"
    DIGITAL_SIGNATURE = "Digital Signature"
    ENCRYPTION = "Encryption"
    DECRYPTION = "Decryption"
    AUTHENTICATION = "Authentication"
    HASHING = "Hashing"
    OTHER = "Other"
    UNKNOWN = "Unknown"

class ConfidenceLevel(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

from typing import List

@dataclass
class AnalysisResult:
    purpose: SemanticPurpose
    confidence: ConfidenceLevel
    evidence: List[str]
    reasoning: str
    manual_review_required: bool
    raw_response: str = ""
