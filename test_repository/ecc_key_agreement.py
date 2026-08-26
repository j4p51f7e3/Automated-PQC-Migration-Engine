from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP256R1())

# In a real scenario, this is received from the peer
peer_public_key = ec.generate_private_key(ec.SECP256R1()).public_key()

shared_secret = private_key.exchange(
    ec.ECDH(),
    peer_public_key
)
