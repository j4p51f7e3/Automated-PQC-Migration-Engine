import hashlib


def create_hash(data):
    return hashlib.md5(data.encode()).hexdigest()