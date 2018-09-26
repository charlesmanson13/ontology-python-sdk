#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base58
from binascii import a2b_hex

from ontology.vm.op_code import CHECKSIG
from ontology.crypto.digest import Digest
from ontology.common.error_code import ErrorCode
from ontology.core.program import ProgramBuilder
from ontology.vm.params_builder import ParamsBuilder
from ontology.exception.exception import SDKException


class Address(object):
    __COIN_VERSION = b'\x17'

    def __init__(self, value):
        """

        :param value:
        :type value: bytes
        """
        self.ZERO = value  # 20 bytes

    @staticmethod
    def to_script_hash(byte_script):
        return a2b_hex(Digest.hash160(msg=byte_script, is_hex=True))

    @staticmethod
    def address_from_bytes_pubkey(public_key):
        """

        :param public_key:
        :type public_key: bytes
        :return:
        """
        builder = ParamsBuilder()
        builder.emit_push_byte_array(bytearray(public_key))
        builder.emit(CHECKSIG)
        addr = Address(Address.to_script_hash(builder.to_array()))
        return addr

    @staticmethod
    def address_from_multi_pub_keys(m, pub_keys):
        """

        :param m:
        :type m: int
        :param pub_keys:
        :type pub_keys: list
        :return:
        """
        return Address(Address.to_script_hash(ProgramBuilder.program_from_multi_pubkey(m, pub_keys)))

    @staticmethod
    def address_from_vm_code(code):
        """
        generate contract address from avm bytecode.
        :param code:
        :type code: basestring
        :return: Address
        """
        return Address(Address.to_script_hash(bytearray.fromhex(code)))

    def b58encode(self):
        script_builder = Address.__COIN_VERSION + self.ZERO
        c256 = Digest.hash256(script_builder)[0:4]
        out_byte_array = script_builder + bytearray(c256)
        out_byte_str = b''.join(map(chr, out_byte_array))
        return base58.b58encode(out_byte_str)

    def to_array(self):
        return self.ZERO

    def to_hex_str(self):
        return self.ZERO.encode('hex')

    def to_reverse_hex_str(self):
        temp = bytearray(self.ZERO)
        temp.reverse()
        return str(temp).encode('hex')

    @staticmethod
    def b58decode(address):
        """

        :param address:
        :type address: basestring
        :return:
        """
        data = base58.b58decode(str(address))

        if len(data) != 25:
            raise SDKException(ErrorCode.param_error)
        if data[0] != Address.__COIN_VERSION:
            raise SDKException(ErrorCode.param_error)
        checksum = Digest.hash256(data[0:21])
        if data[21:25] != checksum[0:4]:
            raise SDKException(ErrorCode.param_error)
        return Address(data[1:21])
