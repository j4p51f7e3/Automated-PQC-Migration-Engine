CRYPTO_RULES = {

    "hashlib.md5": {
        "rule_id": "CRYPTO-001",
        "algorithm": "MD5",
        "category": "Weak Hash Algorithm",
        "severity": "HIGH",
        "description": (
            "MD5 is cryptographically broken and should not "
            "be used for security-sensitive hashing."
        ),
        "recommendation": "SHA-256 or SHA-3"
    },

    "hashlib.sha1": {
        "rule_id": "CRYPTO-002",
        "algorithm": "SHA-1",
        "category": "Weak Hash Algorithm",
        "severity": "HIGH",
        "description": (
            "SHA-1 is deprecated for security-sensitive "
            "applications."
        ),
        "recommendation": "SHA-256 or SHA-3"
    },

    "cryptography.hazmat.primitives.asymmetric.rsa": {
        "rule_id": "CRYPTO-003",
        "algorithm": "RSA",
        "category": "Quantum-Vulnerable Public-Key Cryptography",
        "severity": "HIGH",
        "description": (
            "RSA is vulnerable to sufficiently capable "
            "quantum computers using Shor's algorithm."
        ),
        "recommendation": (
            "Consider a post-quantum migration such as "
            "ML-KEM for key establishment or ML-DSA for "
            "signatures, depending on usage."
        )
    },

    "cryptography.hazmat.primitives.asymmetric.ec": {
        "rule_id": "CRYPTO-004",
        "algorithm": "ECC",
        "category": "Quantum-Vulnerable Public-Key Cryptography",
        "severity": "HIGH",
        "description": (
            "Elliptic-curve public-key cryptography is "
            "vulnerable to sufficiently capable quantum computers."
        ),
        "recommendation": (
            "Consider ML-KEM for key establishment or "
            "ML-DSA/SLH-DSA for signatures, depending on usage."
        )
    }
}