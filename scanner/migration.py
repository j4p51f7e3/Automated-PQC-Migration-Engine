from scanner.migration_rules import MIGRATION_RULES


def get_migration(finding):

    algorithm = finding.algorithm
    usage = finding.usage

    if algorithm not in MIGRATION_RULES:
        return {
            "migration": "Unknown",
            "reason": "No migration rule available."
        }

    rule = MIGRATION_RULES[algorithm]

    # ---------------------------------------------------------
    # MD5 / SHA-1
    # ---------------------------------------------------------

    if algorithm in ["MD5", "SHA-1"]:

        replacement = rule["replacement"]

        return {
            "migration": replacement["algorithm"],
            "alternative": replacement["alternative"],
            "reason": replacement["reason"]
        }

    # ---------------------------------------------------------
    # RSA
    # ---------------------------------------------------------

    if algorithm == "RSA":

        if usage == "Key Establishment":

            migration = rule["key_establishment"]

            return {
                "migration": migration["algorithm"],
                "reason": migration["reason"]
            }

        if usage == "Digital Signature":

            migration = rule["digital_signature"]

            return {
                "migration": migration["algorithm"],
                "reason": migration["reason"]
            }

        return {
            "migration": "Context-dependent",
            "recommended_options": [
                "ML-KEM for key establishment",
                "ML-DSA for digital signatures"
            ],
            "reason": (
                "RSA usage could not be classified precisely."
            )
        }

    # ---------------------------------------------------------
    # ECC
    # ---------------------------------------------------------

    if algorithm == "ECC":

        if usage == "Key Agreement":

            migration = rule["key_agreement"]

            return {
                "migration": migration["algorithm"],
                "reason": migration["reason"]
            }

        if usage == "Digital Signature":

            migration = rule["digital_signature"]

            return {
                "migration": migration["algorithm"],
                "reason": migration["reason"]
            }

        return {
            "migration": "Context-dependent",
            "recommended_options": [
                "ML-KEM for key establishment",
                "ML-DSA for digital signatures"
            ],
            "reason": (
                "ECC usage could not be classified precisely."
            )
        }

    return {
        "migration": "Unknown",
        "reason": "No migration strategy available."
    }