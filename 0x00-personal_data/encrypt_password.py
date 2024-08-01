#!/usr/bin/env python3
""" module
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """hashing password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """checking hash
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
