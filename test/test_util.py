#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import unittest

from ontology.utils import util


class TestUtil(unittest.TestCase):
    def tearDown(self):
        try:
            os.remove('wallet.dat')
        except:
            pass

    def test_get_random_bytes(self):
        try:
            length = -1
            util.get_random_bytes(length)
        except ValueError:
            raised = True
            self.assertTrue(raised, 'Exception raised')
        length = 0
        self.assertEqual(len(util.get_random_bytes(length)), length)
        length = 1
        self.assertEqual(len(util.get_random_bytes(length)), length)
        length = 64
        self.assertEqual(len(util.get_random_bytes(length)), length)
        length = 256
        self.assertEqual(len(util.get_random_bytes(length)), length)
        length = 1024
        self.assertEqual(len(util.get_random_bytes(length)), length)
        length = 2048
        self.assertEqual(len(util.get_random_bytes(length)), length)

    def test_get_random_str(self):
        try:
            length = -1
            util.get_random_str(length)
        except ValueError:
            raised = True
            self.assertTrue(raised, 'Exception raised')
        length = 0
        self.assertEqual(len(util.get_random_str(length)), length)
        length = 1
        self.assertEqual(len(util.get_random_str(length)), length)
        length = 64
        self.assertEqual(len(util.get_random_str(length)), length)
        length = 256
        self.assertEqual(len(util.get_random_str(length)), length)
        length = 1024
        self.assertEqual(len(util.get_random_str(length)), length)
        length = 2048
        self.assertEqual(len(util.get_random_str(length)), length)

    def test_bigint_to_neo_bytes(self):
        bs = util.bigint_to_neo_bytes(-9175052165852779861)
        bs1 = util.bigint_to_neo_bytes(9175052165852779861)
        bs2 = util.bigint_to_neo_bytes(-9199634313818843819)
        bs3 = util.bigint_to_neo_bytes(9199634313818843819)
        bs4 = util.bigint_to_neo_bytes(-8380656)
        bs5 = util.bigint_to_neo_bytes(8380656)
        bs6 = util.bigint_to_neo_bytes(-8446192)
        bs7 = util.bigint_to_neo_bytes(8446192)
        bs8 = util.bigint_to_neo_bytes(-0)
        bs9 = util.bigint_to_neo_bytes(0)
        self.assertEqual(bs.encode('hex'), "abaaaaaaaaaaab80")
        self.assertEqual(bs1.encode('hex'), "555555555555547f")
        self.assertEqual(bs2.encode('hex'), "5555555555555480")
        self.assertTrue(bs3.encode('hex') == "abaaaaaaaaaaab7f")
        self.assertTrue(bs4.encode('hex') == "101f80")
        self.assertTrue(bs5.encode('hex') == "f0e07f")
        self.assertTrue(bs6.encode('hex') == "101f7fff")
        self.assertTrue(bs7.encode('hex') == "f0e08000")
        print(bs8.encode('hex'))
        print(bs9.encode('hex'))


if __name__ == '__main__':
    unittest.main()
