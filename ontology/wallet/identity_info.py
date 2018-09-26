#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class IdentityInfo(object):
    def __init__(self, ont_id="", pubic_key="", encrypted_pri_key="", address_u160="", private_key="", pri_key_wif=""):
        """
        
        :param ont_id:
        :type ont_id: basestring 
        :param pubic_key:
        :type pubic_key: basestring 
        :param encrypted_pri_key:
        :type encrypted_pri_key: basestring 
        :param address_u160:
        :type address_u160: basestring 
        :param private_key:
        :type private_key: basestring 
        :param pri_key_wif:
        :type pri_key_wif: basestring 
        """
        self.ont_id = ont_id
        self.pubic_key = pubic_key
        self.encrypted_pri_key = encrypted_pri_key
        self.address_u160 = address_u160
        self.private_key = private_key
        self.pri_key_wif = pri_key_wif
