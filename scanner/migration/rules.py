from typing import Dict, List, Any

# Map of (Algorithm, Usage) -> Migration Dictionary
MIGRATION_RULES: Dict[str, Dict[str, Any]] = {
    
    # -----------------------------------------------------
    # RSA
    # -----------------------------------------------------
    "RSA:Key Establishment": {
        "migration_type": "PQC Migration",
        "primary_replacement": "ML-KEM",
        "alternative_replacements": [],
        "manual_review_required": False,
        "reason": "RSA used for key establishment should be migrated to ML-KEM."
    },
    "RSA:Key Generation": {
        "migration_type": "PQC Migration",
        "primary_replacement": None,
        "alternative_replacements": ["ML-KEM", "ML-DSA", "SLH-DSA"],
        "manual_review_required": True,
        "reason": "RSA key generation detected. Key generation alone does not reveal whether the key is being used for key establishment (ML-KEM) or digital signatures (ML-DSA / SLH-DSA)."
    },
    "RSA:Digital Signature": {
        "migration_type": "PQC Migration",
        "primary_replacement": "ML-DSA",
        "alternative_replacements": ["SLH-DSA"],
        "manual_review_required": False,
        "reason": "RSA used for digital signatures should be migrated to ML-DSA or SLH-DSA."
    },
    "RSA:Unknown": {
        "migration_type": "PQC Migration",
        "primary_replacement": None,
        "alternative_replacements": ["ML-KEM", "ML-DSA", "SLH-DSA"],
        "manual_review_required": True,
        "reason": "The correct PQC replacement depends on the actual cryptographic purpose."
    },

    # -----------------------------------------------------
    # ECC
    # -----------------------------------------------------
    "ECC:Key Agreement": {
        "migration_type": "PQC Migration",
        "primary_replacement": "ML-KEM",
        "alternative_replacements": [],
        "manual_review_required": False,
        "reason": "ECC used for key agreement should be migrated to ML-KEM."
    },
    "ECC:Key Establishment": {
        "migration_type": "PQC Migration",
        "primary_replacement": "ML-KEM",
        "alternative_replacements": [],
        "manual_review_required": False,
        "reason": "ECC used for key establishment should be migrated to ML-KEM."
    },
    "ECC:Key Generation": {
        "migration_type": "PQC Migration",
        "primary_replacement": None,
        "alternative_replacements": ["ML-KEM", "ML-DSA", "SLH-DSA"],
        "manual_review_required": True,
        "reason": "ECC key generation detected. Key generation alone does not reveal whether the key is being used for key agreement (ML-KEM) or digital signatures (ML-DSA / SLH-DSA)."
    },
    "ECC:Digital Signature": {
        "migration_type": "PQC Migration",
        "primary_replacement": "ML-DSA",
        "alternative_replacements": ["SLH-DSA"],
        "manual_review_required": False,
        "reason": "ECC used for digital signatures should be migrated to ML-DSA or SLH-DSA."
    },
    "ECC:Unknown": {
        "migration_type": "PQC Migration",
        "primary_replacement": None,
        "alternative_replacements": ["ML-KEM", "ML-DSA", "SLH-DSA"],
        "manual_review_required": True,
        "reason": "The correct PQC replacement depends on the actual cryptographic purpose."
    },

    # -----------------------------------------------------
    # WEAK HASHES
    # -----------------------------------------------------
    "MD5:Hashing": {
        "migration_type": "Hash Modernization",
        "primary_replacement": "SHA-256",
        "alternative_replacements": ["SHA-3"],
        "manual_review_required": False,
        "reason": "MD5 is cryptographically broken and should be replaced with a modern hash like SHA-256 or SHA-3."
    },
    "SHA-1:Hashing": {
        "migration_type": "Hash Modernization",
        "primary_replacement": "SHA-256",
        "alternative_replacements": ["SHA-3"],
        "manual_review_required": False,
        "reason": "SHA-1 is deprecated and should be replaced with a modern hash like SHA-256 or SHA-3."
    }
}
