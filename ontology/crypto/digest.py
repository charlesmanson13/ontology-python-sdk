#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib


class Digest(object):
    @staticmethod
    def __sha256(msg, is_hex=False):
        """

        :param msg:
        :type msg: bytes
        :param is_hex:
        :type is_hex: bool
        :return:
        """
        m = hashlib.sha256()
        m.update(msg)
        if is_hex:
            return m.hexdigest()
        else:
            return m.digest()

    @staticmethod
    def ripemd160(msg, is_hex=False):
        """

        :param msg:
        :type msg: bytes
        :param is_hex:
        :type is_hex: bool
        :return:
        """
        h = hashlib.new('ripemd160')
        h.update(msg)
        if is_hex:
            return h.hexdigest()
        else:
            return h.digest()

    @staticmethod
    def sha256(msg, offset=0, length=0, is_hex=False):
        """

        :param msg:
        :type msg: bytes
        :param offset:
        :type offset: int
        :param length:
        :type length: int
        :param is_hex:
        :type is_hex: bool
        :return:
        """
        if offset != 0 and len(msg) > offset + length:
            msg = msg[offset:offset + length]
        return Digest.__sha256(msg, is_hex)

    @staticmethod
    def hash256(msg, is_hex=False):
        """

        :param msg:
        :type msg: bytes
        :param is_hex:
        :type is_hex: bool
        :return: bytes | bytestring
        """
        digest = Digest.sha256(Digest.sha256(msg), is_hex=is_hex)
        return digest

    @staticmethod
    def hash160(msg, is_hex=False):
        """

        :param msg:
        :type msg: bytes
        :param is_hex:
        :type is_hex: bool
        :return: bytes | bytestring
        """
        digest = Digest.ripemd160(Digest.__sha256(msg), is_hex)
        return digest
