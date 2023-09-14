# coding: utf-8

"""
ASN.1 type classes for various algorithms using in various aspects of public
key cryptography. Exports the following items:

 - AlgorithmIdentifier()
 - AnyAlgorithmIdentifier()
 - DigestAlgorithm()
 - DigestInfo()
 - DSASignature()
 - EncryptionAlgorithm()
 - HmacAlgorithm()
 - KdfAlgorithm()
 - Pkcs5MacAlgorithm()
 - SignedDigestAlgorithm()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._errors import unwrap
# from ._int import fill_width
# from .util import int_from_bytes, int_to_bytes
from .core import (
    Any,
    Choice,
    Integer,
    Null,
    ObjectIdentifier,
    OctetString,
    Sequence,
    Void,
)


# Structures and OIDs in this file are pulled from
# https://tools.ietf.org/html/rfc3279, https://tools.ietf.org/html/rfc4055,
# https://tools.ietf.org/html/rfc5758, https://tools.ietf.org/html/rfc7292,
# http://www.emc.com/collateral/white-papers/h11302-pkcs5v2-1-password-based-cryptography-standard-wp.pdf

class AlgorithmIdentifier(Sequence):
    _fields = [
        ('algorithm', ObjectIdentifier),
        ('parameters', Any, {'optional': True}),
    ]


class _ForceNullParameters(object):
    """
    Various structures based on AlgorithmIdentifier require that the parameters
    field be core.Null() for certain OIDs. This mixin ensures that happens.
    """

    # The following attribute, plus the parameters spec callback and custom
    # __setitem__ are all to handle a situation where parameters should not be
    # optional and must be Null for certain OIDs. More info at
    # https://tools.ietf.org/html/rfc4055#page-15 and
    # https://tools.ietf.org/html/rfc4055#section-2.1
    _null_algos = set([
        '1.2.840.113549.1.1.1',    # rsassa_pkcs1v15 / rsaes_pkcs1v15 / rsa
        '1.2.840.113549.1.1.11',   # sha256_rsa
        '1.2.840.113549.1.1.12',   # sha384_rsa
        '1.2.840.113549.1.1.13',   # sha512_rsa
        '1.2.840.113549.1.1.14',   # sha224_rsa
        '1.3.14.3.2.26',           # sha1
        '2.16.840.1.101.3.4.2.4',  # sha224
        '2.16.840.1.101.3.4.2.1',  # sha256
        '2.16.840.1.101.3.4.2.2',  # sha384
        '2.16.840.1.101.3.4.2.3',  # sha512
    ])

    def _parameters_spec(self):
        if self._oid_pair == ('algorithm', 'parameters'):
            algo = self['algorithm'].native
            if algo in self._oid_specs:
                return self._oid_specs[algo]

        if self['algorithm'].dotted in self._null_algos:
            return Null

        return None

    _spec_callbacks = {
        'parameters': _parameters_spec
    }

    # We have to override this since the spec callback uses the value of
    # algorithm to determine the parameter spec, however default values are
    # assigned before setting a field, so a default value can't be based on
    # another field value (unless it is a default also). Thus we have to
    # manually check to see if the algorithm was set and parameters is unset,
    # and then fix the value as appropriate.
    def __setitem__(self, key, value):
        res = super(_ForceNullParameters, self).__setitem__(key, value)
        if key != 'algorithm':
            return res
        if self['algorithm'].dotted not in self._null_algos:
            return res
        if self['parameters'].__class__ != Void:
            return res
        self['parameters'] = Null()
        return res



class DigestAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.2.2': 'md2',
        '1.2.840.113549.2.5': 'md5',
        '1.3.14.3.2.26': 'sha1',
        '2.16.840.1.101.3.4.2.4': 'sha224',
        '2.16.840.1.101.3.4.2.1': 'sha256',
        '2.16.840.1.101.3.4.2.2': 'sha384',
        '2.16.840.1.101.3.4.2.3': 'sha512',
        '2.16.840.1.101.3.4.2.5': 'sha512_224',
        '2.16.840.1.101.3.4.2.6': 'sha512_256',
        '2.16.840.1.101.3.4.2.7': 'sha3_224',
        '2.16.840.1.101.3.4.2.8': 'sha3_256',
        '2.16.840.1.101.3.4.2.9': 'sha3_384',
        '2.16.840.1.101.3.4.2.10': 'sha3_512',
        '2.16.840.1.101.3.4.2.11': 'shake128',
        '2.16.840.1.101.3.4.2.12': 'shake256',
        '2.16.840.1.101.3.4.2.17': 'shake128_len',
        '2.16.840.1.101.3.4.2.18': 'shake256_len',
    }


class DigestAlgorithm(_ForceNullParameters, Sequence):
    _fields = [
        ('algorithm', DigestAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


# This structure is what is signed with a SignedDigestAlgorithm
class DigestInfo(Sequence):
    _fields = [
        ('digest_algorithm', DigestAlgorithm),
        ('digest', OctetString),
    ]


class SignedDigestAlgorithmId(ObjectIdentifier):
    _map = {
        '1.3.14.3.2.3': 'md5_rsa',
        '1.3.14.3.2.29': 'sha1_rsa',
        '1.3.14.7.2.3.1': 'md2_rsa',
        '1.2.840.113549.1.1.2': 'md2_rsa',
        '1.2.840.113549.1.1.4': 'md5_rsa',
        '1.2.840.113549.1.1.5': 'sha1_rsa',
        '1.2.840.113549.1.1.14': 'sha224_rsa',
        '1.2.840.113549.1.1.11': 'sha256_rsa',
        '1.2.840.113549.1.1.12': 'sha384_rsa',
        '1.2.840.113549.1.1.13': 'sha512_rsa',
        '1.2.840.113549.1.1.10': 'rsassa_pss',
        '1.2.840.10040.4.3': 'sha1_dsa',
        '1.3.14.3.2.13': 'sha1_dsa',
        '1.3.14.3.2.27': 'sha1_dsa',
        # Source: NIST CSOR Algorithm Registrations
        '2.16.840.1.101.3.4.3.1': 'sha224_dsa',
        '2.16.840.1.101.3.4.3.2': 'sha256_dsa',
        '2.16.840.1.101.3.4.3.3': 'sha384_dsa',
        '2.16.840.1.101.3.4.3.4': 'sha512_dsa',
        '1.2.840.10045.4.1': 'sha1_ecdsa',
        '1.2.840.10045.4.3.1': 'sha224_ecdsa',
        '1.2.840.10045.4.3.2': 'sha256_ecdsa',
        '1.2.840.10045.4.3.3': 'sha384_ecdsa',
        '1.2.840.10045.4.3.4': 'sha512_ecdsa',
        # Source: NIST CSOR Algorithm Registrations
        '2.16.840.1.101.3.4.3.5': 'sha3_224_dsa',
        '2.16.840.1.101.3.4.3.6': 'sha3_256_dsa',
        '2.16.840.1.101.3.4.3.7': 'sha3_384_dsa',
        '2.16.840.1.101.3.4.3.8': 'sha3_512_dsa',
        '2.16.840.1.101.3.4.3.9': 'sha3_224_ecdsa',
        '2.16.840.1.101.3.4.3.10': 'sha3_256_ecdsa',
        '2.16.840.1.101.3.4.3.11': 'sha3_384_ecdsa',
        '2.16.840.1.101.3.4.3.12': 'sha3_512_ecdsa',
        '2.16.840.1.101.3.4.3.13': 'sha3_224_rsa',
        '2.16.840.1.101.3.4.3.14': 'sha3_256_rsa',
        '2.16.840.1.101.3.4.3.15': 'sha3_384_rsa',
        '2.16.840.1.101.3.4.3.16': 'sha3_512_rsa',
        # For when the digest is specified elsewhere in a Sequence
        '1.2.840.113549.1.1.1': 'rsassa_pkcs1v15',
        '1.2.840.10040.4.1': 'dsa',
        '1.2.840.10045.4': 'ecdsa',
        # RFC 8410 -- https://tools.ietf.org/html/rfc8410
        '1.3.101.112': 'ed25519',
        '1.3.101.113': 'ed448',
        '1.3.6.1.4.1.2.267.7.4.4':'dilithium2',
    }

    _reverse_map = {
        'dsa': '1.2.840.10040.4.1',
        'ecdsa': '1.2.840.10045.4',
        'md2_rsa': '1.2.840.113549.1.1.2',
        'md5_rsa': '1.2.840.113549.1.1.4',
        'rsassa_pkcs1v15': '1.2.840.113549.1.1.1',
        'rsassa_pss': '1.2.840.113549.1.1.10',
        'sha1_dsa': '1.2.840.10040.4.3',
        'sha1_ecdsa': '1.2.840.10045.4.1',
        'sha1_rsa': '1.2.840.113549.1.1.5',
        'sha224_dsa': '2.16.840.1.101.3.4.3.1',
        'sha224_ecdsa': '1.2.840.10045.4.3.1',
        'sha224_rsa': '1.2.840.113549.1.1.14',
        'sha256_dsa': '2.16.840.1.101.3.4.3.2',
        'sha256_ecdsa': '1.2.840.10045.4.3.2',
        'sha256_rsa': '1.2.840.113549.1.1.11',
        'sha384_dsa': '2.16.840.1.101.3.4.3.3',
        'sha384_ecdsa': '1.2.840.10045.4.3.3',
        'sha384_rsa': '1.2.840.113549.1.1.12',
        'sha512_dsa': '2.16.840.1.101.3.4.3.4',
        'sha512_ecdsa': '1.2.840.10045.4.3.4',
        'sha512_rsa': '1.2.840.113549.1.1.13',
        # Source: NIST CSOR Algorithm Registrations
        'sha3_224_dsa': '2.16.840.1.101.3.4.3.5',
        'sha3_256_dsa': '2.16.840.1.101.3.4.3.6',
        'sha3_384_dsa': '2.16.840.1.101.3.4.3.7',
        'sha3_512_dsa': '2.16.840.1.101.3.4.3.8',
        'sha3_224_ecdsa': '2.16.840.1.101.3.4.3.9',
        'sha3_256_ecdsa': '2.16.840.1.101.3.4.3.10',
        'sha3_384_ecdsa': '2.16.840.1.101.3.4.3.11',
        'sha3_512_ecdsa': '2.16.840.1.101.3.4.3.12',
        'sha3_224_rsa': '2.16.840.1.101.3.4.3.13',
        'sha3_256_rsa': '2.16.840.1.101.3.4.3.14',
        'sha3_384_rsa': '2.16.840.1.101.3.4.3.15',
        'sha3_512_rsa': '2.16.840.1.101.3.4.3.16',
        'ed25519': '1.3.101.112',
        'ed448': '1.3.101.113',
        'dilithium2':'1.3.6.1.4.1.2.267.7.4.4',
    }


class SignedDigestAlgorithm(_ForceNullParameters, Sequence):
    _fields = [
        ('algorithm', SignedDigestAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    @property
    def signature_algo(self):
        """
        :return:
            A unicode string of "rsassa_pkcs1v15", "rsassa_pss", "dsa",
            "ecdsa", "ed25519" or "ed448"
        """

        algorithm = self['algorithm'].native

        algo_map = {
            'md2_rsa': 'rsassa_pkcs1v15',
            'md5_rsa': 'rsassa_pkcs1v15',
            'sha1_rsa': 'rsassa_pkcs1v15',
            'sha224_rsa': 'rsassa_pkcs1v15',
            'sha256_rsa': 'rsassa_pkcs1v15',
            'sha384_rsa': 'rsassa_pkcs1v15',
            'sha512_rsa': 'rsassa_pkcs1v15',
            'sha3_224_rsa': 'rsassa_pkcs1v15',
            'sha3_256_rsa': 'rsassa_pkcs1v15',
            'sha3_384_rsa': 'rsassa_pkcs1v15',
            'sha3_512_rsa': 'rsassa_pkcs1v15',
            'rsassa_pkcs1v15': 'rsassa_pkcs1v15',
            'rsassa_pss': 'rsassa_pss',
            'sha1_dsa': 'dsa',
            'sha224_dsa': 'dsa',
            'sha256_dsa': 'dsa',
            'sha384_dsa': 'dsa',
            'sha512_dsa': 'dsa',
            'sha3_224_dsa': 'dsa',
            'sha3_256_dsa': 'dsa',
            'sha3_384_dsa': 'dsa',
            'sha3_512_dsa': 'dsa',
            'dsa': 'dsa',
            'sha1_ecdsa': 'ecdsa',
            'sha224_ecdsa': 'ecdsa',
            'sha256_ecdsa': 'ecdsa',
            'sha384_ecdsa': 'ecdsa',
            'sha512_ecdsa': 'ecdsa',
            'sha3_224_ecdsa': 'ecdsa',
            'sha3_256_ecdsa': 'ecdsa',
            'sha3_384_ecdsa': 'ecdsa',
            'sha3_512_ecdsa': 'ecdsa',
            'ecdsa': 'ecdsa',
            'ed25519': 'ed25519',
            'ed448': 'ed448',
            'dilithium2':'dilithium2',
        }
        if algorithm in algo_map:
            return algo_map[algorithm]

        raise ValueError(unwrap(
            '''
            Signature algorithm not known for %s
            ''',
            algorithm
        ))

    @property
    def hash_algo(self):
        """
        :return:
            A unicode string of "md2", "md5", "sha1", "sha224", "sha256",
            "sha384", "sha512", "sha512_224", "sha512_256" or "shake256"
        """

        algorithm = self['algorithm'].native

        algo_map = {
            'md2_rsa': 'md2',
            'md5_rsa': 'md5',
            'sha1_rsa': 'sha1',
            'sha224_rsa': 'sha224',
            'sha256_rsa': 'sha256',
            'sha384_rsa': 'sha384',
            'sha512_rsa': 'sha512',
            'sha1_dsa': 'sha1',
            'sha224_dsa': 'sha224',
            'sha256_dsa': 'sha256',
            'sha384_dsa': 'sha384',
            'sha512_dsa': 'sha512',
            'sha1_ecdsa': 'sha1',
            'sha224_ecdsa': 'sha224',
            'sha256_ecdsa': 'sha256',
            'sha384_ecdsa': 'sha384',
            'sha512_ecdsa': 'sha512',
            'sha3_224_dsa': 'sha3_224',
            'sha3_256_dsa': 'sha3_256',
            'sha3_384_dsa': 'sha3_384',
            'sha3_512_dsa': 'sha3_512',
            'sha3_224_ecdsa': 'sha3_224',
            'sha3_256_ecdsa': 'sha3_256',
            'sha3_384_ecdsa': 'sha3_384',
            'sha3_512_ecdsa': 'sha3_512',
            'sha3_224_rsa': 'sha3_224',
            'sha3_256_rsa': 'sha3_256',
            'sha3_384_rsa': 'sha3_384',
            'sha3_512_rsa': 'sha3_512',
            'ed25519': 'sha512',
            'ed448': 'shake256',
        }
        if algorithm in algo_map:
            return algo_map[algorithm]

        if algorithm == 'rsassa_pss':
            return self['parameters']['hash_algorithm']['algorithm'].native

        raise ValueError(unwrap(
            '''
            Hash algorithm not known for %s
            ''',
            algorithm
        ))


class AnyAlgorithmId(ObjectIdentifier):
    _map = {}

    def _setup(self):
        _map = self.__class__._map
        for other_cls in (SignedDigestAlgorithmId, DigestAlgorithmId):
            for oid, name in other_cls._map.items():
                _map[oid] = name


class AnyAlgorithmIdentifier(_ForceNullParameters, Sequence):
    _fields = [
        ('algorithm', AnyAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {}

    def _setup(self):
        Sequence._setup(self)
        specs = self.__class__._oid_specs
        for other_cls in (SignedDigestAlgorithm):
            for oid, spec in other_cls._oid_specs.items():
                specs[oid] = spec
