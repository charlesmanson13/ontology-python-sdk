#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class AccountData(object):
    def __init__(self, address='', enc_alg="aes-256-gcm", key="", algorithm="ECDSA", salt="", param=None, label="",
                 public_key="", sign_scheme="SHA256withECDSA", is_default=True, lock=False):
        """
        
        :param address:
        :type address: basestring 
        :param enc_alg: 
        :type enc_alg: basestring
        :param key: 
        :type key: basestring
        :param algorithm: 
        :type algorithm: basestring
        :param salt: 
        :type salt: basestring
        :param param: 
        :type param: dict
        :param label: 
        :type label: basestring
        :param public_key: 
        :type public_key: basestring
        :param sign_scheme: 
        :type sign_scheme: basestring
        :param is_default: 
        :type is_default: bool
        :param lock: 
        :type lock: bool
        """
        if param is None:
            param = {"curve": "P-256"}
        self.address = address
        self.algorithm = algorithm
        self.enc_alg = enc_alg
        self.is_default = is_default
        self.key = key
        self.label = label
        self.lock = lock
        self.parameters = param
        self.salt = salt
        self.public_key = public_key
        self.signature_scheme = sign_scheme

    def __iter__(self):
        data = dict()
        data['address'] = self.address
        data['algorithm'] = self.algorithm
        data['enc-alg'] = self.enc_alg
        data['isDefault'] = self.is_default
        data['key'] = self.key
        data['label'] = self.label
        data['lock'] = self.lock
        data['parameters'] = self.parameters
        data['salt'] = self.salt
        data['publicKey'] = self.public_key
        data['signatureScheme'] = self.signature_scheme
        for key, value in data.items():
            yield (key, value)

    def set_label(self, label):
        """

        :param label:
        :type label: basestring
        :return:
        """
        self.label = label

    def set_address(self, address):
        self.address = address

    def set_public_key(self, public_key):
        self.public_key = public_key

    def set_key(self, key):
        self.key = key

    def get_label(self):
        return self.label

    def get_address(self):
        return self.address

    def get_public_key_bytes(self):
        return self.public_key

    def get_key(self):
        return self.key
