from cryptography.hazmat.primitives.asymmetric import ec


def generate_key():
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    return private_key