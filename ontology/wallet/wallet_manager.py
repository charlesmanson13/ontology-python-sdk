#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import uuid
import base64
from datetime import datetime

from ontology.common.define import DID_ONT
from ontology.crypto.scrypt import Scrypt
from ontology.wallet.control import Control
from ontology.common.address import Address
from ontology.account.account import Account
from ontology.utils.util import is_file_exist
from ontology.wallet.wallet import WalletData
from ontology.utils.util import get_random_str
from ontology.wallet.account import AccountData
from ontology.common.error_code import ErrorCode
from ontology.wallet.account_info import AccountInfo
from ontology.exception.exception import SDKException
from ontology.wallet.identity import Identity, did_ont
from ontology.wallet.identity_info import IdentityInfo
from ontology.crypto.signature_scheme import SignatureScheme


class WalletManager(object):
    def __init__(self, scheme=SignatureScheme.SHA256withECDSA):
        self.scheme = scheme
        self.wallet_file = WalletData()
        self.wallet_in_mem = WalletData()
        self.wallet_path = ""

    def open_wallet(self, wallet_path):
        """

        :param wallet_path:
        :type wallet_path: basestring
        :return:
        """
        self.wallet_path = wallet_path
        if is_file_exist(wallet_path) is False:
            # create a new wallet file
            self.wallet_in_mem.create_time = datetime.today().strftime("%Y-%m-%d %H:%M:%S")
            self.save()
        # wallet file exists now
        self.wallet_file = self.load()
        self.wallet_in_mem = self.wallet_file
        return self.wallet_file

    def load(self):
        with open(self.wallet_path, "r") as f:
            obj = json.load(f)
            try:
                create_time = obj['createTime']
            except KeyError:
                create_time = ''
            try:
                default_id = obj['defaultOntid']
            except KeyError:
                default_id = ''
            try:
                default_address = obj['defaultAccountAddress']
            except KeyError:
                default_address = ''
            try:
                identities = obj['identities']
            except KeyError:
                identities = list()
            try:
                wallet = WalletData(obj['name'], obj['version'], create_time, default_id, default_address,
                                    obj['scrypt'], identities, obj['accounts'])
            except KeyError as e:
                raise SDKException(ErrorCode.param_err('wallet file format error: %s.' % e))
        return wallet

    def save(self):
        with open(self.wallet_path, "w") as f:
            json.dump(self.wallet_in_mem, f, default=lambda obj: dict(obj), indent=4)

    def get_wallet(self):
        return self.wallet_in_mem

    def write_wallet(self):
        self.save()
        self.wallet_file = self.wallet_in_mem
        return self.wallet_file

    def reset_wallet(self):
        self.wallet_in_mem = self.wallet_file.clone()
        return self.wallet_in_mem

    def get_signature_scheme(self):
        return self.scheme

    def set_signature_scheme(self, scheme):
        self.scheme = scheme

    def import_identity(self, label, encrypted_pri_key, pwd, salt, b58_address):
        """
        This interface is used to import identity by providing encrypted private key, password, salt and
        base58 encode address which should be correspond to the encrypted private key provided.

        :param label: a label for identity.
        :type label: basestring
        :param encrypted_pri_key: an encrypted private key in base64 encoding from.
        :type encrypted_pri_key: basestring
        :param pwd: a password which is used to encrypt and decrypt the private key.
        :type pwd: basestring
        :param salt: a salt value which will be used in the process of encrypt private key.
        :type salt: basestring
        :param b58_address: a base58 encode address which correspond with the encrypted private key provided.
        :type b58_address: basestring
        :return: Identity | None if succeed, an Identity object will be returned.
        """
        scrypt_n = Scrypt().get_n()
        pri_key = Account.get_gcm_decoded_private_key(encrypted_pri_key, pwd, b58_address, salt, scrypt_n, self.scheme)
        info = self.__create_identity(label, pwd, salt, pri_key)
        for index in range(len(self.wallet_in_mem.identities)):
            if self.wallet_in_mem.identities[index].ont_id == info.ont_id:
                return self.wallet_in_mem.identities[index]
        return None

    def create_identity(self, label, pwd):
        """

        :param label: a label for identity.
        :type label: basestring
        :param pwd: a password which will be used to encrypt and decrypt the private key.
        :type pwd: basestring
        :return: Identity
        """
        pri_key = get_random_str(64)
        salt = get_random_str(16)
        return self.__create_identity(label, pwd, salt, pri_key)

    def __create_identity(self, label, pwd, salt, private_key):
        """

        :param label:
        :type label: basestring
        :param pwd:
        :type pwd: basestring
        :param salt:
        :type salt: basestring
        :param private_key:
        :type private_key: basestring
        :return:
        """
        acct = self.__create_account(label, pwd, salt, private_key, False)
        info = IdentityInfo()
        info.ont_id = did_ont + acct.get_address_base58()
        info.pubic_key = acct.serialize_public_key().encode('hex')
        info.private_key = acct.serialize_private_key().encode('hex')
        info.pri_key_wif = acct.export_wif().encode('ascii')
        info.encrypted_pri_key = acct.export_gcm_encrypted_private_key(pwd, salt, Scrypt().get_n())
        info.address_u160 = acct.get_address().to_array().encode('hex')
        return self.wallet_in_mem.get_identity_by_ont_id(info.ont_id)

    def create_identity_from_private_key(self, label, pwd, private_key):
        """
        This interface is used to create identity based on given label, password and private key.

        :param label: a label for identity.
        :type label: basestring
        :param pwd: a password which will be used to encrypt and decrypt the private key.
        :type pwd: basestring
        :param private_key: a private key in the form of string.
        :type private_key: basestring
        :return: Identity
        """
        salt = get_random_str(16)
        identity = self.__create_identity(label, pwd, salt, private_key)
        return identity

    def create_account(self, label, pwd):
        """
        This interface is used to create account based on given password and label.

        :param label: a label for account.
        :type label: basestring
        :param pwd: a password which will be used to encrypt and decrypt the private key
        :type pwd: basestring
        :return: AccountData
        """
        pri_key = get_random_str(64)
        salt = get_random_str(16)
        account = self.__create_account(label, pwd, salt, pri_key, True)
        return self.wallet_in_mem.get_account_by_address(account.get_address_base58())

    def __create_account(self, label, pwd, salt, private_key, account_flag):
        """

        :param label:
        :type label: basestring
        :param pwd:
        :type pwd: basestring
        :param salt:
        :type salt: basestring
        :param private_key:
        :type private_key: basestring
        :param account_flag:
        :type account_flag: bool
        :return:
        """
        account = Account(private_key, self.scheme)
        # initialization
        if self.scheme == SignatureScheme.SHA256withECDSA:
            acct = AccountData()
        else:
            raise ValueError("scheme type is error")
        # set key
        if pwd is not None:
            acct.key = account.export_gcm_encrypted_private_key(pwd, salt, Scrypt().get_n())
        else:
            acct.key = account.serialize_private_key().encode('hex')

        acct.address = account.get_address_base58()
        # set label
        if label is None or label == "":
            label = str(uuid.uuid4())[0:8]
        if account_flag:
            for index in range(len(self.wallet_in_mem.accounts)):
                if acct.address == self.wallet_in_mem.accounts[index].address:
                    raise ValueError("wallet account exists")

            if len(self.wallet_in_mem.accounts) == 0:
                acct.is_default = True
                self.wallet_in_mem.default_account_address = acct.address
            acct.label = label
            acct.salt = base64.b64encode(salt).decode('ascii')
            acct.public_key = account.serialize_public_key().encode('hex')
            self.wallet_in_mem.accounts.append(acct)
        else:
            for index in range(len(self.wallet_in_mem.identities)):
                if self.wallet_in_mem.identities[index].ont_id == did_ont + acct.address:
                    raise ValueError("wallet identity exists")
            idt = Identity()
            idt.ont_id = did_ont + acct.address
            idt.label = label
            if len(self.wallet_in_mem.identities) == 0:
                idt.is_default = True
                self.wallet_in_mem.default_ont_id = idt.ont_id
            ctl = Control(id="keys-1", key=acct.key, salt=base64.b64encode(salt.encode()).decode('ascii'),
                          address=acct.address,
                          public_key=account.serialize_public_key().encode('hex'))
            idt.controls.append(ctl)
            self.wallet_in_mem.identities.append(idt)
        return account

    def import_account(self, label, encrypted_pri_key, pwd, base58_address, base64_salt):
        """
        This interface is used to import account by providing account data.

        :param label: str, wallet label
        :type label: basestring
        :param encrypted_pri_key: str, an encrypted private key in base64 encoding from
        :type encrypted_pri_key: basestring
        :param pwd: str, a password which is used to encrypt and decrypt the private key
        :type pwd: basestring
        :param base58_address: str, a base58 encode  wallet address value
        :type base58_address: basestring
        :param base64_salt: str, a base64 encode salt value which is used in the encryption of private key
        :type base64_salt: basestring
        :return: AccountData | None
            if succeed, return an data structure which contain the information of a wallet account.
            if failed, return a None object.
        """
        salt = base64.b64decode(base64_salt.encode('ascii')).decode('latin-1')
        private_key = Account.get_gcm_decoded_private_key(encrypted_pri_key, pwd, base58_address, salt,
                                                          Scrypt().get_n(),
                                                          self.scheme)
        info = self.create_account_info(label, pwd, salt, private_key)
        for index in range(len(self.wallet_in_mem.accounts)):
            if info.address_base58 == self.wallet_in_mem.accounts[index].address:
                return self.wallet_in_mem.accounts[index]
        return None

    def create_account_info(self, label, pwd, salt, private_key):
        """

        :param label:
        :type label: basestring
        :param pwd:
        :type pwd: basestring
        :param salt:
        :type salt: basestring
        :param private_key:
        :type private_key: basestring
        :return: AccountInfo
        """
        acct = self.__create_account(label, pwd, salt, private_key, True)
        info = AccountInfo()
        info.address_base58 = Address.address_from_bytes_pubkey(acct.serialize_public_key()).b58encode()
        info.public_key = acct.serialize_public_key().encode('hex')
        info.encrypted_pri_key = acct.export_gcm_encrypted_private_key(pwd, salt, Scrypt().get_n())
        info.address_u160 = acct.get_address().to_array().encode('hex')
        info.salt = salt
        return info

    def create_account_from_private_key(self, label, password, private_key):
        """
        This interface is used to create account by providing an encrypted private key and it's decrypt password.

        :param label: a label for account.
        :type label: basestring
        :param password: a password which is used to decrypt the encrypted private key.
        :type password: basestring
        :param private_key: a private key in the form of string.
        :type private_key: basestring
        :return: AccountData | None
        """
        salt = get_random_str(16)
        info = self.create_account_info(label, password, salt, private_key)
        for index in range(len(self.wallet_in_mem.accounts)):
            if info.address_base58 == self.wallet_in_mem.accounts[index].address:
                return self.wallet_in_mem.accounts[index]
        return None

    def get_account(self, b58_address_or_ontid, password):
        """
        :param b58_address_or_ontid: a base58 encode address or ontid
        :type b58_address_or_ontid: basestring
        :param password: a password which is used to decrypt the encrypted private key.
        :type address: basestring
        :return: Account | None
        """
        if b58_address_or_ontid.startswith(DID_ONT):
            for index in range(len(self.wallet_in_mem.identities)):
                if self.wallet_in_mem.identities[index].ont_id == b58_address_or_ontid:
                    addr = self.wallet_in_mem.identities[index].ont_id.replace(did_ont, "")
                    key = self.wallet_in_mem.identities[index].controls[0].key
                    salt = base64.b64decode(self.wallet_in_mem.identities[index].controls[0].salt)
                    private_key = Account.get_gcm_decoded_private_key(key, password, addr, salt, Scrypt().get_n(),
                                                                      self.scheme)
                    return Account(private_key, self.scheme)
        else:
            for index in range(len(self.wallet_in_mem.accounts)):
                if self.wallet_in_mem.accounts[index].address == b58_address_or_ontid:
                    key = self.wallet_in_mem.accounts[index].key
                    addr = self.wallet_in_mem.accounts[index].address
                    salt = base64.b64decode(self.wallet_in_mem.accounts[index].salt)
                    private_key = Account.get_gcm_decoded_private_key(key, password, addr, salt, Scrypt().get_n(), self.scheme)
                    return Account(private_key, self.scheme)
        return None

    def get_default_identity(self):
        """

        :return: Identity
        """
        for identity in self.wallet_in_mem.identities:
            if identity.is_default:
                return identity
        raise SDKException(ErrorCode.param_error)

    def get_default_account(self):
        """
        This interface is used to get the default account in WalletManager.

        :return: AccountData
        """
        for acct in self.wallet_in_mem.accounts:
            if acct.is_default:
                return acct
        raise SDKException(ErrorCode.get_default_account_err)
