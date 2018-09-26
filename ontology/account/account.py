#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import binascii

import base58
from binascii import b2a_hex, a2b_hex

from ontology.crypto.curve import Curve
from ontology.crypto.digest import Digest
from ontology.crypto.scrypt import Scrypt
from ontology.common.address import Address
from ontology.crypto.key_type import KeyType
from ontology.crypto.signature import Signature
from ontology.crypto.aes_handler import AESHandler
from ontology.crypto.signature_scheme import SignatureScheme
from ontology.crypto.signature_handler import SignatureHandler


class Account(object):
    def __init__(self, private_key, scheme=SignatureScheme.SHA256withECDSA):
        """

        :param private_key:
        :type private_key: basestring
        :param scheme:
        :type scheme: SignatureScheme
        """
        self.__signature_scheme = scheme
        if scheme == SignatureScheme.SHA256withECDSA:
            self.__keyType = KeyType.ECDSA
        elif scheme == SignatureScheme.SHA3_384withECDSA:
            self.__keyType = KeyType.ECDSA
        elif scheme == SignatureScheme.SHA3_384withECDSA:
            self.__keyType = KeyType.ECDSA
        elif scheme == SignatureScheme.SHA512withECDSA:
            self.__keyType = KeyType.ECDSA
        elif scheme == SignatureScheme.SHA3_224withECDSA:
            self.__keyType = KeyType.ECDSA
        else:
            raise TypeError
        self.__private_key = a2b_hex(private_key.encode())  # 32 bytes
        self.__curve_name = Curve.P256
        self.__publicKey = Signature.ec_get_pubkey_by_prikey(self.__private_key, self.__curve_name)  # 33 bytes
        self.__address = Address.address_from_bytes_pubkey(self.__publicKey)  # address is a class type

    def generate_signature(self, msg, signature_scheme):
        """

        :param msg:
        :type msg: bytes
        :param signature_scheme:
        :type signature_scheme: SignatureScheme
        :return:
        """
        if signature_scheme == SignatureScheme.SHA256withECDSA:
            handler = SignatureHandler(self.__keyType, signature_scheme)
            signature_value = handler.generateSignature(b2a_hex(self.__private_key), msg)
            byte_signature = Signature(signature_scheme, signature_value).to_byte()
        else:
            raise TypeError
        return byte_signature

    def get_address(self):
        """

        :return:
        """
        return self.__address  # __address is a class not a string or bytes

    def get_address_base58(self):
        """
        This interface is used to get the base58 encode account address.

        :return: basestring
        """
        return self.__address.b58encode()

    def get_address_hex(self):
        """
        This interface is used to get the little-endian hexadecimal account address.

        :return: little-endian hexadecimal account address.
        """
        return self.__address.to_hex_str()

    def get_address_hex_reverse(self):
        """
        This interface is used to get the big-endian hexadecimal account address.

        :return: big-endian hexadecimal account address.
        """
        return self.__address.to_reverse_hex_str()

    def get_public_key_bytes(self):
        """
        This interface is used to get the account's public key in the form of bytes.

        :return: bytes the public key in the form of bytes.
        """
        return self.__publicKey

    def get_public_key_hex(self):
        """
        This interface is used to get the account's hexadecimal public key in the form of string.

        :return: basestring the hexadecimal public key in the form of string.
        """
        return binascii.b2a_hex(self.__publicKey).decode('ascii')

    def get_signature_scheme(self):
        """
        This interface allow to get he signature scheme used in account

        :return: SignatureScheme he signature scheme used in account.
        """
        return self.__signature_scheme

    def export_gcm_encrypted_private_key(self, password, salt, n):
        """
        This interface is used to export an AES algorithm encrypted private key with the mode of GCM.

        :param password: the secret pass phrase to generate the keys from.
        :type password: basestring
        :param salt: A string to use for better protection from dictionary attacks.
                      This value does not need to be kept secret, but it should be randomly chosen for each derivation.
                      It is recommended to be at least 8 bytes long.
        :type salt: basestring
        :param n: CPU/memory cost parameter. It must be a power of 2 and less than 2**32
        :type n: int
        :return: basestring an gcm encrypted private key in the form of string.
        """
        r = 8
        p = 8
        dk_len = 64
        scrypt = Scrypt(n, r, p, dk_len)
        derivedkey = scrypt.generate_kd(password, salt)
        iv = derivedkey[0:12]
        derivedhalf2 = derivedkey[32:64]
        mac_tag, cipher_text = AESHandler.aes_gcm_encrypt_with_iv(self.__private_key,
                                                                  self.__address.b58encode().encode(),
                                                                  derivedhalf2,
                                                                  iv)
        encrypted_key = b2a_hex(cipher_text) + b2a_hex(mac_tag)
        encrypted_key_str = base64.b64encode(a2b_hex(encrypted_key))
        return encrypted_key_str.decode()

    @staticmethod
    def get_gcm_decoded_private_key(encrypted_key_str, password, b58_address, salt, n, scheme):
        """
        This interface is used to decrypt an private key which has been encrypted.

        :param encrypted_key_str: an gcm encrypted private key in the form of string.
        :type encrypted_key_str: basestring
        :param password: the secret pass phrase to generate the keys from.
        :type password: basestring
        :param b58_address: a base58 encode address which should be correspond with the private key.
        :type b58_address: basestring
        :param salt: a string to use for better protection from dictionary attacks.
        :type salt: basestring
        :param n: CPU/memory cost parameter.
        :type n: int
        :param scheme: the signature scheme.
        :type scheme: SignatureScheme
        :return: basestring a private key in the form of string.
        """
        r = 8
        p = 8
        dk_len = 64
        scrypt = Scrypt(n, r, p, dk_len)
        derivedkey = scrypt.generate_kd(password, salt)
        iv = derivedkey[0:12]
        derivedhalf2 = derivedkey[32:64]
        encrypted_key = base64.b64decode(encrypted_key_str).encode('hex')
        mac_tag = a2b_hex(encrypted_key[64:96])
        cipher_text = a2b_hex(encrypted_key[0:64])
        pri_key = AESHandler.aes_gcm_decrypt_with_iv(cipher_text, b58_address.encode(), mac_tag, derivedhalf2, iv)
        pri_key = b2a_hex(pri_key).decode('ascii')
        acct = Account(pri_key, scheme)
        if acct.get_address().b58encode() != b58_address:
            raise RuntimeError
        return pri_key

    def serialize_private_key(self):
        """
        This interface is used to get the private key in the form of bytes.

        :return: the private key in the form of bytes.
        """
        return self.__private_key

    def serialize_public_key(self):
        """
        This interface is used to get the public key in the form of bytes.

        :return: bytes the public key in the form of bytes.
        """
        return self.__publicKey

    def export_wif(self):
        """
        This interface is used to get export ECDSA private key in the form of WIF which
        is a way to encoding an ECDSA private key and make it easier to copy.

        :return: basestring a WIF encode private key.
        """
        data = b'\x80'
        data = data + self.serialize_private_key()
        data += b'\01'
        checksum = Digest.hash256(data[0:34])
        data += checksum[0:4]
        wif = base58.b58encode(data)
        return wif.decode('ascii')

    @staticmethod
    def get_private_key_from_wif(wif):
        """
        This interface is used to decode a WIF encode ECDSA private key.

        :param wif: a WIF encode private key.
        :type wif: basestring
        :return: bytes a ECDSA private key in the form of bytes.
        """
        if wif is None or wif is "":
            raise Exception("none wif")
        data = base58.b58decode(wif)
        if len(data) != 38 or data[0] != '\x80' or data[33] != '\x01':
            raise Exception("wif wrong")
        checksum = Digest.hash256(data[0:34])
        for i in range(4):
            if data[- 4 + i] != checksum[i]:
                raise Exception("wif wrong")
        return data[1:33]
