"""
Class with all available hashing methods
"""
import hashlib


def sha256_hash(filepath: str) -> str:
    """
    SHA256 Hash
    """
    try:
        sha256_hash_object: object = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash_object.update(byte_block)
            return sha256_hash_object.hexdigest()
    except FileNotFoundError:
        return 'File not found'


def sha512_hash(filepath: str) -> str:
    """
    SHA512 Hash
    """
    try:
        sha512_hash_object: object = hashlib.sha512()
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha512_hash_object.update(byte_block)
            return sha512_hash_object.hexdigest()
    except FileNotFoundError:
        return 'File not found'


def sha1_hash(filepath: str) -> str:
    """
    SHA1 Hash
    """
    try:
        sha1_hash_object: object = hashlib.sha1()
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha1_hash_object.update(byte_block)
            return sha1_hash_object.hexdigest()
    except FileNotFoundError:
        return 'File not found'


def md5_hash(filepath: str) -> str:
    """
    MD5 Hash
    """
    try:
        md5_hash_object: object = hashlib.md5()
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                md5_hash_object.update(byte_block)
            return md5_hash_object.hexdigest()
    except FileNotFoundError:
        return 'File not found'
