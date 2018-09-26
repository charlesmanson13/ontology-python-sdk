#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class ProgramInfo(object):

    def __init__(self):
        self.pubkeys = []
        self.m = 0

    def set_pubkey(self, pubkeys):
        """

        :param pubkeys:
        :type pubkeys: list
        :return:
        """
        self.pubkeys = pubkeys

    def set_m(self, m):
        self.m = m
