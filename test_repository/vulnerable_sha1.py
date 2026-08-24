import hashlib


def create_hash(data):
    return hashlib.sha1(data.encode()).hexdigest()