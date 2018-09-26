#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ontology.core.program_info import ProgramInfo
from ontology.crypto.key_type import KeyType
from ontology.io.binary_reader import BinaryReader
from ontology.vm.op_code import PUSHBYTES75, PUSHBYTES1, PUSHDATA1, PUSHDATA2, PUSHDATA4, CHECKSIG, CHECKMULTISIG, PUSH1
from ontology.io.binary_writer import BinaryWriter
from ontology.io.memory_stream import StreamManager
from ontology.utils.util import bytes_reader
from ontology.vm.params_builder import ParamsBuilder
from ecdsa import util
from ontology.common import define


class ProgramBuilder(object):

    @staticmethod
    def program_from_params(sigs):
        code = bytearray()
        for sig in sigs:
            code += ProgramBuilder.push_bytes(sig)
        return code

    @staticmethod
    def program_from_pubkey(public_key):
        builder = ParamsBuilder()
        builder.emit_push_byte_array(public_key)
        builder.emit(CHECKSIG)
        return builder.to_array()

    @staticmethod
    def push_bytes(data):
        ms = StreamManager.GetStream()
        writer = BinaryWriter(ms)
        if len(data) == 0:
            raise ValueError("push data error: data is null")
        if len(data) <= ord(PUSHBYTES75) + 1 - ord(PUSHBYTES1):
            num = len(data) + ord(PUSHBYTES1) - 1
            writer.write_byte(num)
        elif len(data) < 0x100:
            writer.write_byte(PUSHDATA1)
            writer.write_uint8(len(data))
        elif len(data) < 0x10000:
            writer.write_byte(PUSHDATA2)
            writer.write_uint16(len(data))
        else:
            writer.write_byte(PUSHDATA4)
            writer.write_uint32(len(data))
        writer.write_bytes(data)
        ms.flush()
        res = ms.ToArray()
        StreamManager.ReleaseStream(ms)
        res = bytes_reader(res)
        return res

    @staticmethod
    def read_bytes(reader):
        """

        :param reader:
        :type reader: BinaryReader
        :return:
        """
        code = reader.read_byte()
        key_len = 0
        if code == ord(PUSHDATA4):
            temp = reader.read_uint32()
            key_len = temp
        elif code == ord(PUSHDATA2):
            temp = reader.read_uint16()
            key_len = int(temp)
        elif code == ord(PUSHDATA1):
            temp = reader.read_uint8()
            key_len = int(temp)
        elif ord(PUSHBYTES1) <= code <= ord(PUSHBYTES75):
            key_len = code - ord(PUSHBYTES1) + 1
        else:
            key_len = 0
        res = reader.read_bytes(key_len)
        return res

    @staticmethod
    def compare_pubkey(o1):
        if KeyType.from_pubkey(o1) == KeyType.SM2:
            raise Exception("not supported")
        elif KeyType.from_pubkey(o1) == KeyType.ECDSA:
            x = o1[1:]
            return util.string_to_number(x)
        else:
            return str(o1)

    @staticmethod
    def sort_publickeys(publicKeys):
        """

        :param publicKeys:
        :type publicKeys: list
        :return:
        """
        return sorted(publicKeys, key=ProgramBuilder.compare_pubkey)

    @staticmethod
    def program_from_multi_pubkey(m, pubkeys):
        """

        :param m:
        :type m: int
        :param pubkeys:
        :type pubkeys: list
        :return:
        """
        n = len(pubkeys)
        if m <= 0 or m > n or n > define.MULTI_SIG_MAX_PUBKEY_SIZE:
            raise Exception("param error")
        builder = ParamsBuilder()
        builder.emit_push_integer(m)
        pubkeys = ProgramBuilder.sort_publickeys(pubkeys)
        for pubkey in pubkeys:
            builder.emit_push_byte_array(pubkey)
        builder.emit_push_integer(n)
        builder.emit(CHECKMULTISIG)
        return builder.to_array()

    @staticmethod
    def get_param_info(program):
        """

        :param program:
        :type program: bytes
        :return: list
        """
        ms = StreamManager.GetStream(program)
        reader = BinaryReader(ms)
        list = []
        while True:
            try:
                res = ProgramBuilder.read_bytes(reader)
            except:
                break
            list.append(res)
        return list

    @staticmethod
    def get_program_info(program):
        """

        :param program:
        :type program: bytes
        :return: ProgramInfo
        """
        length = len(program)
        end = program[length - 1]
        temp = program[:length - 1]
        ms = StreamManager.GetStream(temp)
        reader = BinaryReader(ms)
        info = ProgramInfo()
        if end == ord(CHECKSIG):
            pubkeys = ProgramBuilder.read_bytes(reader)
            info.set_pubkey([pubkeys])
            info.set_m(1)
        elif end == ord(CHECKMULTISIG):
            length = program[len(program) - 2] - ord(PUSH1)
            m = reader.read_byte() - ord(PUSH1) + 1
            pub = []
            for i in range(length):
                pub.append(reader.read_var_bytes())
            info.set_pubkey(pub)
            info.set_m(m)
        return info
