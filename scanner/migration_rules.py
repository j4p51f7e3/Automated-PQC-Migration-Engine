MIGRATION_RULES = {

    "RSA": {

        "quantum_safe": True,

        "key_establishment": {
            "algorithm": "ML-KEM",
            "reason": (
                "RSA-based key establishment is vulnerable "
                "to quantum attacks."
            )
        },

        "digital_signature": {
            "algorithm": "ML-DSA",
            "reason": (
                "RSA signatures are vulnerable to sufficiently "
                "capable quantum computers."
            )
        }
    },

    "ECC": {

        "quantum_safe": True,

        "key_agreement": {
            "algorithm": "ML-KEM",
            "reason": (
                "Elliptic-curve key agreement is vulnerable "
                "to quantum attacks."
            )
        },

        "digital_signature": {
            "algorithm": "ML-DSA",
            "reason": (
                "Elliptic-curve signatures are vulnerable "
                "to quantum attacks."
            )
        },

        "key_generation": {
            "algorithm": "ML-KEM / ML-DSA",
            "reason": (
                "The correct PQC replacement depends on whether "
                "the generated key is subsequently used for "
                "key establishment or digital signatures."
            )
        }
    },

    "MD5": {

        "quantum_safe": False,

        "replacement": {
            "algorithm": "SHA-256",
            "alternative": "SHA-3",
            "reason": (
                "MD5 is cryptographically broken and should "
                "not be used for security-sensitive hashing."
            )
        }
    },

    "SHA-1": {

        "quantum_safe": False,

        "replacement": {
            "algorithm": "SHA-256",
            "alternative": "SHA-3",
            "reason": (
                "SHA-1 is deprecated for security-sensitive "
                "applications."
            )
        }
    }
}