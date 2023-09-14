# coding: utf-8

"""
ASN.1 type classes for public and private keys. Exports the following items:

 - DSAPrivateKey()
 - ECPrivateKey()
 - EncryptedPrivateKeyInfo()
 - PrivateKeyInfo()
 - PublicKeyInfo()
 - RSAPrivateKey()
 - RSAPublicKey()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import math

from ._errors import unwrap, APIException

# _types doesnt use anything from asn
from ._types import type_name, byte_cls
# algos uses _errors and .core
from .algos import _ForceNullParameters, DigestAlgorithm, EncryptionAlgorithm, RSAESOAEPParams, RSASSAPSSParams
from .core import (
    Any,
    Asn1Value,
    BitString,
    Choice,
    Integer,
    IntegerOctetString,
    Null,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    ParsableOctetString,
    ParsableOctetBitString,
    Sequence,
    SequenceOf,
    SetOf,
)



class PublicKeyAlgorithmId(ObjectIdentifier):
    """
    Original Name: None
    Source: https://tools.ietf.org/html/rfc3279
    """

    _map = {
        '1.3.6.1.4.1.2.267.7.4.4':'dilithium2',
    }


class PublicKeyAlgorithm(_ForceNullParameters, Sequence):
    """
    Original Name: AlgorithmIdentifier
    Source: https://tools.ietf.org/html/rfc5280#page-18
    """

    _fields = [
        ('algorithm', PublicKeyAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class PublicKeyInfo(Sequence):
    """
    Original Name: SubjectPublicKeyInfo
    Source: https://tools.ietf.org/html/rfc5280#page-17
    """

    _fields = [
        ('algorithm', PublicKeyAlgorithm),
        ('public_key', ParsableOctetBitString),
    ]

    def _public_key_spec(self):
        algorithm = self['algorithm']['algorithm'].native
        ## this will returm the type of subjectPUblicKey
        return {
            'dilithium2':(OctetBitString, None),
        }[algorithm]

    _spec_callbacks = {
        'public_key': _public_key_spec
    }

    _algorithm = None
    _bit_size = None
    _fingerprint = None
    _sha1 = None
    _sha256 = None

    @classmethod
    def wrap(cls, public_key, algorithm):
        """
        Wraps a public key in a PublicKeyInfo structure

        :param public_key:
            A byte string or Asn1Value object of the public key

        :param algorithm:
            A unicode string of "rsa"

        :return:
            A PublicKeyInfo object
        """

        if not isinstance(public_key, byte_cls) and not isinstance(public_key, Asn1Value):
            raise TypeError(unwrap(
                '''
                public_key must be a byte string or Asn1Value, not %s
                ''',
                type_name(public_key)
            ))

        # if algorithm != 'rsa' and algorithm != 'rsassa_pss':
        #     raise ValueError(unwrap(
        #         '''
        #         algorithm must "rsa", not %s
        #         ''',
        #         repr(algorithm)
        #     ))
        
        algo = PublicKeyAlgorithm()
        algo['algorithm'] = PublicKeyAlgorithmId(algorithm)
        if algorithm !='dilithium2':
            algo['parameters'] = Null()

        container = cls()
        container['algorithm'] = algo
        if isinstance(public_key, Asn1Value):
            public_key = public_key.untag().dump()
        container['public_key'] = ParsableOctetBitString(public_key)
        # container['public_key'] = OctetBitString(public_key)

        return container

    def unwrap(self):
        """
        Unwraps an RSA public key into an RSAPublicKey object. Does not support
        DSA or EC public keys since they do not have an unwrapped form.

        :return:
            An RSAPublicKey object
        """

        raise APIException(
            'asn1crypto.keys.PublicKeyInfo().unwrap() has been removed, '
            'please use oscrypto.asymmetric.PublicKey().unwrap() instead')

 
    @property
    def algorithm(self):
        """
        :return:
            A unicode string of "rsa", "rsassa_pss", "dsa" or "ec"
        """

        if self._algorithm is None:
            self._algorithm = self['algorithm']['algorithm'].native
        return self._algorithm

    @property
    def bit_size(self):
        """
        :return:
            The bit size of the public key, as an integer
        """

        if self._bit_size is None:
            if self.algorithm == 'ec':
                self._bit_size = int(((len(self['public_key'].native) - 1) / 2) * 8)
            else:
                if self.algorithm == 'rsa' or self.algorithm == 'rsassa_pss':
                    prime = self['public_key'].parsed['modulus'].native
                elif self.algorithm == 'dsa':
                    prime = self['algorithm']['parameters']['p'].native
                self._bit_size = int(math.ceil(math.log(prime, 2)))
                modulus = self._bit_size % 8
                if modulus != 0:
                    self._bit_size += 8 - modulus

        return self._bit_size

    @property
    def byte_size(self):
        """
        :return:
            The byte size of the public key, as an integer
        """

        return int(math.ceil(self.bit_size / 8))

    @property
    def sha1(self):
        """
        :return:
            The SHA1 hash of the DER-encoded bytes of this public key info
        """

        if self._sha1 is None:
            self._sha1 = hashlib.sha1(byte_cls(self['public_key'])).digest()
        return self._sha1

    @property
    def sha256(self):
        """
        :return:
            The SHA-256 hash of the DER-encoded bytes of this public key info
        """

        if self._sha256 is None:
            self._sha256 = hashlib.sha256(byte_cls(self['public_key'])).digest()
        return self._sha256
