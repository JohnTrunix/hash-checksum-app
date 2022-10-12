"""
Class with all available hashing methods
"""
import hashlib


def sha256_hash(filepath):
    """
    SHA256 Hash
    """
    sha256_hash_object = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            sha256_hash_object.update(byte_block)
        return sha256_hash_object.hexdigest()


def sha512_hash(filepath):
    """
    SHA512 Hash
    """
    sha512_hash_object = hashlib.sha512()
    with open(filepath, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            sha512_hash_object.update(byte_block)
        return sha512_hash_object.hexdigest()


def sha1_hash(filepath):
    """
    SHA1 Hash
    """
    sha1_hash_object = hashlib.sha1()
    with open(filepath, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            sha1_hash_object.update(byte_block)
        return sha1_hash_object.hexdigest()


def md5_hash(filepath):
    """
    MD5 Hash
    """
    md5_hash_object = hashlib.md5()
    with open(filepath, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            md5_hash_object.update(byte_block)
        return md5_hash_object.hexdigest()
