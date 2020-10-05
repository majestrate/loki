#!/usr/bin/env pytest

from pycryptonote import crypto


def yield_keys(n):
    """ generator that generates n keypairs """
    while n > 0:
        yield crypto.generate_keys()
        n -= 1

def mk_keys(n):
    """ make a list of keypairs n items long """
    keys = []
    for k in yield_keys(n):
        keys.append(k)
    return keys

def test_ch_fast_hash():
    h = crypto.cn_fast_hash("test")
    assert h.to_hex() is not None

def test_generate_key_derivation():
    keys = mk_keys(2)
    kd0_1 = keys[1][0].generate_key_derivation(keys[0][1])
    kd1_0 = keys[0][0].generate_key_derivation(keys[1][1])
    assert kd0_1 == kd1_0
    
