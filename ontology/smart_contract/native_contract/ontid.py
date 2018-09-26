from collections import OrderedDict
from time import time

from ontology.account.account import Account
from ontology.vm import build_vm
from ontology.core.transaction import Transaction
from ontology.crypto.key_type import KeyType
from ontology.common.address import Address
from ontology.common.define import *
from ontology.io.memory_stream import StreamManager
from ontology.io.binary_reader import BinaryReader
from ontology.crypto.curve import Curve
from binascii import b2a_hex, a2b_hex

from ontology.wallet.identity import Identity


class OntId(object):
    def __init__(self, sdk):
        self.__sdk = sdk

    @staticmethod
    def new_registry_ont_id_transaction(ont_id, hex_public_key, b58_payer_address, gas_limit, gas_price):
        """
        This interface is used to generate a Transaction object which is used to register ONT ID.

        :param ont_id: ontid.
        :type ont_id: basestring
        :param hex_public_key: the hexadecimal public key in the form of string.
        :type hex_public_key: basestring
        :param b58_payer_address: a base58 encode address which indicate who will pay for the transaction.
        :type b58_payer_address: basestring
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a Transaction object which is used to register ONT ID.
        """
        contract_address = ONTID_CONTRACT_ADDRESS
        args = {"ontid": ont_id.encode(), "pubkey": bytearray.fromhex(hex_public_key)}
        invoke_code = build_vm.build_native_invoke_code(contract_address, chr(0), "regIDWithPublicKey", args)
        unix_time_now = int(time())
        tx = Transaction(0, 0xd1, unix_time_now, gas_price, gas_limit, Address.b58decode(b58_payer_address).to_array(),
                         invoke_code, bytearray(), [], bytearray())
        return tx

    def send_registry_ont_id_transaction(self, identity, password, payer, gas_limit, gas_price):
        """
        This interface is used to send a Transaction object which is used to registry ontid.

        :param identity: an Identity object.
        :type identity: Identity
        :param password: a password which is used to decrypt the encrypted private key.
        :type password: basestring
        :param payer: an Account object which indicate who will pay for the transaction.
        :type payer: Account
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a hexadecimal transaction hash value.
        """
        tx = OntId.new_registry_ont_id_transaction(identity.ont_id, identity.controls[0].public_key,
                                                   payer.get_address_base58(), gas_limit, gas_price)
        account = self.__sdk.wallet_manager.get_account(identity.ont_id, password)
        self.__sdk.sign_transaction(tx, account)
        self.__sdk.add_sign_transaction(tx, payer)
        return self.__sdk.rpc.send_raw_transaction(tx)

    @staticmethod
    def new_add_attribute_transaction(ont_id, hex_public_key, attribute_list, b58_payer_address, gas_limit, gas_price):
        """
        This interface is used to generate a Transaction object which is used to add attribute.

        :param ont_id: ontid.
        :type ont_id: basestring
        :param hex_public_key: the hexadecimal public key in the form of string.
        :type hex_public_key: basestring
        :param attribute_list: a list of attributes we want to add.
        :type attribute_list: list
        :param b58_payer_address: a base58 encode address which indicate who will pay for the transaction.
        :type b58_payer_address: basestring
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a Transaction object which is used to add attribute.
        """
        contract_address = ONTID_CONTRACT_ADDRESS
        args = OrderedDict([("ontid", ont_id.encode()), ("length", len(attribute_list))])
        for i in range(len(attribute_list)):
            args["key" + str(i)] = bytes(attribute_list[i]["key"].encode())
            args["type" + str(i)] = bytes(attribute_list[i]["type"].encode())
            args["value" + str(i)] = bytes(attribute_list[i]["value"].encode())
        args["pubkey"] = bytearray.fromhex(hex_public_key)
        invoke_code = build_vm.build_native_invoke_code(contract_address, chr(0), "addAttributes", args)
        unix_time_now = int(time())
        array_payer_address = Address.b58decode(str(b58_payer_address)).to_array()
        tx = Transaction(0, 0xd1, unix_time_now, gas_price, gas_limit, array_payer_address, invoke_code, bytearray(),
                         [], bytearray())
        return tx

    def send_add_attribute_transaction(self, identity, password, attribute_list, payer, gas_limit, gas_price):
        """
        This interface is used to send a Transaction object which is used to add attribute.

        :param identity: an Identity object.
        :type identity: Identity
        :param password: a password which is used to decrypt the encrypted private key.
        :type password: basestring
        :param attribute_list: a list of attributes we want to add.
        :type attribute_list: list
        :param payer: an Account object which indicate who will pay for the transaction.
        :type payer: Account
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: basestring a hexadecimal transaction hash value.
        """
        tx = OntId.new_add_attribute_transaction(identity.ont_id, identity.controls[0].public_key, attribute_list,
                                                 payer.get_address_base58(), gas_limit, gas_price)
        account = self.__sdk.wallet_manager.get_account(identity.ont_id, password)
        self.__sdk.sign_transaction(tx, account)
        self.__sdk.add_sign_transaction(tx, payer)
        tx_hash = self.__sdk.rpc.send_raw_transaction(tx)
        return tx_hash

    @staticmethod
    def new_remove_attribute_transaction(ont_id, hex_public_key, path, b58_payer_address, gas_limit, gas_price):
        """
        This interface is used to generate a Transaction object which is used to remove attribute.

        :param ont_id: ontid.
        :type ont_id: basestring
        :param hex_public_key: the hexadecimal public key in the form of string.
        :type hex_public_key: basestring
        :param path: a string which is used to indicate which attribute we want to remove.
        :type path: basestring
        :param b58_payer_address: a base58 encode address which indicate who will pay for the transaction.
        :type b58_payer_address: basestring
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a Transaction object which is used to remove attribute.
        """
        contract_address = ONTID_CONTRACT_ADDRESS
        args = OrderedDict([
            ("ontid", ont_id.encode()),
            ("key", bytes(path.encode())),
            ("pubkey", bytearray.fromhex(hex_public_key))])
        invoke_code = build_vm.build_native_invoke_code(contract_address, chr(0), "removeAttribute", args)
        unix_time_now = int(time())
        tx = Transaction(0, 0xd1, unix_time_now, gas_price, gas_limit, Address.b58decode(b58_payer_address).to_array(),
                         invoke_code, bytearray(), [], bytearray())
        return tx

    def send_remove_attribute_transaction(self, identity, password, path, payer, gas_limit, gas_price):
        """
        This interface is used to send a Transaction object which is used to remove attribute.

        :param identity: an Identity object.
        :type identity: Identity
        :param password: a password which is used to decrypt the encrypted private key.
        :type password: basestring
        :param path: a string which is used to indicate which attribute we want to remove.
        :type path: basestring
        :param payer: an Account object which indicate who will pay for the transaction.
        :type payer: Account
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a hexadecimal transaction hash value.
        """
        tx = OntId.new_remove_attribute_transaction(identity.ont_id, identity.controls[0].public_key, path,
                                                    payer.get_address_base58(), gas_limit, gas_price)
        account = self.__sdk.wallet_manager.get_account(identity.ont_id, password)
        self.__sdk.sign_transaction(tx, account)
        self.__sdk.add_sign_transaction(tx, payer)
        return self.__sdk.rpc.send_raw_transaction(tx)

    @staticmethod
    def new_add_public_key_transaction(ont_id, hex_public_key_or_recovery, hex_new_public_key,
                                       payer, gas_limit, gas_price):
        """
        This interface is used to send a Transaction object which is used to add public key.

        :param ont_id: ontid.
        :type ont_id: basestring
        :param hex_public_key_or_recovery: the old hexadecimal public key in the form of string.
        :type hex_public_key_or_recovery: basestring
        :param hex_new_public_key: the new hexadecimal public key in the form of string.
        :type hex_new_public_key: basestring
        :param payer: an Account object which indicate who will pay for the transaction.
        :type payer: basestring
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a Transaction object which is used to add public key.
        """
        contract_address = ONTID_CONTRACT_ADDRESS
        args = OrderedDict([
            ("ontid", ont_id.encode()),
            ("pubkey", bytearray.fromhex(hex_new_public_key)),
            ("pubkey_or_recovery", bytearray.fromhex(hex_public_key_or_recovery))])
        invoke_code = build_vm.build_native_invoke_code(contract_address, chr(0), "addKey", args)
        unix_time_now = int(time())
        tx = Transaction(0, 0xd1, unix_time_now, gas_price, gas_limit, Address.b58decode(payer).to_array(),
                         invoke_code, bytearray(), [], bytearray())
        return tx

    def send_add_public_key_transaction(self, identity, password, new_hex_public_key, payer, gas_limit, gas_price):
        """
        This interface is used to send a Transaction object which is used to add public key.

        :param identity: an Identity object.
        :type identity: Identity
        :param password: a password which is used to decrypt the encrypted private key.
        :type password: basestring
        :param new_hex_public_key: the new hexadecimal public key in the form of string.
        :type new_hex_public_key: basestring
        :param payer: an Account object which indicate who will pay for the transaction.
        :type payer: Account
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return:  a hexadecimal transaction hash value.
        """
        tx = OntId.new_add_public_key_transaction(identity.ont_id, identity.controls[0].public_key, new_hex_public_key,
                                                  payer.get_address_base58(), gas_limit, gas_price)
        account = self.__sdk.wallet_manager.get_account(identity.ont_id, password)
        self.__sdk.sign_transaction(tx, account)
        self.__sdk.add_sign_transaction(tx, payer)
        return self.__sdk.rpc.send_raw_transaction(tx)

    def send_add_public_key_by_recovery(self, ont_id, recovery, hex_new_public_key, payer, gas_limit, gas_price):
        """
        This interface is used to send a Transaction object which is used to add public key
        based on the recovery account.

        :param ont_id: ontid.
        :type ont_id: basestring
        :param recovery: an Account object which used a recovery account.
        :type recovery: Account
        :param hex_new_public_key: the new hexadecimal public key in the form of string.
        :type hex_new_public_key: basestring
        :param payer: an Account object which indicate who will pay for the transaction.
        :type payer: Account
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a hexadecimal transaction hash value.
        """
        b58_payer_address = payer.get_address_base58()
        hex_recovery_address = recovery.get_address().to_hex_str()
        tx = OntId.new_add_public_key_transaction(ont_id, hex_recovery_address, hex_new_public_key, b58_payer_address,
                                                  gas_limit, gas_price)
        self.__sdk.sign_transaction(tx, recovery)
        self.__sdk.add_sign_transaction(tx, payer)
        tx_hash = self.__sdk.rpc.send_raw_transaction(tx)
        return tx_hash

    @staticmethod
    def new_remove_public_key_transaction(ont_id, hex_public_key_or_recovery, hex_remove_public_key,
                                          b58_payer_address, gas_limit, gas_price):
        """
        This interface is used to generate a Transaction object which is used to remove public key.

        :param ont_id: ontid.
        :type ont_id: basestring
        :param hex_public_key_or_recovery: the hexadecimal public key in the form of string.
        :type hex_public_key_or_recovery: basestring
        :param hex_remove_public_key: a hexadecimal public key string which will be removed.
        :type hex_remove_public_key: basestring
        :param b58_payer_address: a base58 encode address which indicate who will pay for the transaction.
        :type b58_payer_address: basestring
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a Transaction object which is used to remove public key.
        """
        contract_address = ONTID_CONTRACT_ADDRESS
        bytes_public_key_or_recovery = bytearray.fromhex(hex_public_key_or_recovery)
        bytes_remove_public_key = bytearray.fromhex(hex_remove_public_key)
        bytes_ont_id = ont_id.encode()
        args = OrderedDict([
            ("ontid", bytes_ont_id),
            ("pubkey", bytes_remove_public_key),
            ("pubkey_or_recovery", bytes_public_key_or_recovery)])
        invoke_code = build_vm.build_native_invoke_code(contract_address, chr(0), "removeKey", args)
        unix_time_now = int(time())
        bytes_payer_address = Address.b58decode(b58_payer_address).to_array()
        tx = Transaction(0, 0xd1, unix_time_now, gas_price, gas_limit, bytes_payer_address, invoke_code, bytearray(),
                         [], bytearray())
        return tx

    def send_remove_public_key_transaction(self, identity, password, hex_remove_public_key, payer, gas_limit, gas_price):
        """
        This interface is used to send a Transaction object which is used to remove public key.

        :param identity: an Identity object.
        :type identity: Identity
        :param password: a password which is used to decrypt the encrypted private key.
        :type password: basestring
        :param hex_remove_public_key: a hexadecimal public key string which will be removed.
        :type hex_remove_public_key: basestring
        :param payer: an Account object which indicate who will pay for the transaction.
        :type payer: Account
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a hexadecimal transaction hash value.
        """
        b58_payer_address = payer.get_address_base58()
        tx = OntId.new_remove_public_key_transaction(identity.ont_id, identity.controls[0].public_key,
                                                     hex_remove_public_key, b58_payer_address, gas_limit, gas_price)
        account = self.__sdk.wallet_manager.get_account(identity.ont_id, password)
        self.__sdk.sign_transaction(tx, account)
        self.__sdk.add_sign_transaction(tx, payer)
        return self.__sdk.rpc.send_raw_transaction(tx)

    def send_remove_public_key_transaction_by_recovery(self, ont_id, recovery, hex_remove_public_key, payer,
                                                       gas_limit, gas_price):
        """

        :param ont_id:
        :type ont_id: basestring
        :param recovery:
        :type recovery: Account
        :param hex_remove_public_key:
        :type hex_remove_public_key: basestring
        :param payer:
        :type payer: basestring
        :param gas_limit:
        :type gas_limit: int
        :param gas_price:
        :type gas_price: int
        :return:
        """
        bytes_recovery_address = recovery.get_address().to_array()
        b58_payer_address = payer.get_address_base58()
        tx = OntId.new_remove_public_key_transaction(ont_id, bytes_recovery_address, hex_remove_public_key,
                                                     b58_payer_address, gas_limit, gas_price)
        self.__sdk.sign_transaction(tx, recovery)
        if recovery.get_address_base58() != payer.get_address_base58():
            self.__sdk.add_sign_transaction(tx, payer)
        return self.__sdk.rpc.send_raw_transaction(tx)

    @staticmethod
    def new_add_recovery_transaction(ont_id, hex_public_key, b58_recovery_address,
                                     b58_payer_address, gas_limit, gas_price):
        """
        This interface is used to generate a Transaction object which is used to add the recovery.

        :param ont_id: ontid.
        :type ont_id: basestring
        :param hex_public_key: the hexadecimal public key in the form of string.
        :type hex_public_key: basestring
        :param b58_recovery_address: a base58 encode address which indicate who is the recovery.
        :type b58_recovery_address: basestring
        :param b58_payer_address: a base58 encode address which indicate who will pay for the transaction.
        :type b58_payer_address: basestring
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return:
        """
        contract_address = ONTID_CONTRACT_ADDRESS
        bytes_recovery_address = Address.b58decode(b58_recovery_address).to_array()
        bytearray_public_key = bytearray.fromhex(hex_public_key)
        args = OrderedDict([
            ("ontid", ont_id.encode()),
            ("recovery", bytes_recovery_address),
            ("pubkey", bytearray_public_key)
        ])
        invoke_code = build_vm.build_native_invoke_code(contract_address, chr(0), "addRecovery", args)
        unix_time_now = int(time())
        bytes_payer_address = Address.b58decode(b58_payer_address).to_array()
        tx = Transaction(0, 0xd1, unix_time_now, gas_price, gas_limit, bytes_payer_address, invoke_code, bytearray(),
                         [], bytearray())
        return tx

    def send_add_recovery_transaction(self, identity, password, b58_recovery_address, payer, gas_limit, gas_price):
        """
        This interface is used to send a Transaction object which is used to add the recovery.

        :param identity: an Identity object.
        :type identity: Identity
        :param password: a password which is used to decrypt the encrypted private key.
        :type password: basestring
        :param b58_recovery_address: a base58 encode address which indicate who is the recovery.
        :type b58_recovery_address: basestring
        :param payer: an Account object which indicate who will pay for the transaction.
        :type payer: Account
        :param gas_limit: an int value that indicate the gas limit.
        :type gas_limit: int
        :param gas_price: an int value that indicate the gas price.
        :type gas_price: int
        :return: a Transaction object which is used to add the recovery.
        """
        b58_payer_address = payer.get_address_base58()
        tx = OntId.new_add_recovery_transaction(identity.ont_id, identity.controls[0].public_key, b58_recovery_address,
                                                b58_payer_address, gas_limit, gas_price)
        account = self.__sdk.wallet_manager.get_account(identity.ont_id, password)
        self.__sdk.sign_transaction(tx, account)
        self.__sdk.add_sign_transaction(tx, payer)
        tx_hash = self.__sdk.rpc.send_raw_transaction(tx)
        return tx_hash

    @staticmethod
    def new_get_ddo_transaction(ont_id):
        """
        This interface is used to generate a Transaction object which is used to get
        a hexadecimal serialize DDO object.

        :param ont_id: ontid.
        :type ont_id: basestring
        :return: a hexadecimal serialize DDO object string.
        """
        contract_address = ONTID_CONTRACT_ADDRESS
        args = {"ontid": ont_id.encode()}
        invoke_code = build_vm.build_native_invoke_code(contract_address, chr(0), "getDDO", args)
        unix_time_now = int(time())
        payer = Address(a2b_hex("0000000000000000000000000000000000000000".encode())).to_array()
        return Transaction(0, 0xd1, unix_time_now, 0, 0, payer, invoke_code, bytearray(),
                           [], bytearray())

    def send_get_ddo(self, ont_id):
        """
        This interface is used to get a DDO object in the from of dict.

        :param ont_id: ontid.
        :type ont_id: basestring
        :return: dict a DDO object in the from of dict.
        """
        tx = OntId.new_get_ddo_transaction(ont_id)
        res = self.__sdk.rpc.send_raw_transaction_pre_exec(tx)
        return OntId.parse_ddo(ont_id, res)

    @staticmethod
    def parse_ddo(ont_id, ddo):
        """
        This interface is used to deserialize a hexadecimal string into a DDO object in the from of dict.

        :param ont_id: ontid.
        :type ont_id: basestring
        :param ddo:  an hexadecimal string.
        :type ddo: basestring
        :return: dict a DDO object in the from of dict.
        """
        if ddo == "":
            return dict()
        ms = StreamManager.GetStream(a2b_hex(ddo))
        reader = BinaryReader(ms)
        try:
            public_key_bytes = reader.read_var_bytes()
        except Exception as e:
            raise e
        try:
            attribute_bytes = reader.read_var_bytes()
        except Exception as e:
            attribute_bytes = bytearray()
        try:
            recovery_bytes = reader.read_var_bytes()
        except Exception as e:
            recovery_bytes = bytearray()
        pubKey_list = []
        if len(public_key_bytes) != 0:
            ms = StreamManager.GetStream(public_key_bytes)
            reader2 = BinaryReader(ms)
            while True:
                try:
                    index = reader2.read_int32()
                    d = {}
                    d['PubKeyId'] = ont_id + "#keys-" + str(index)
                    pubkey = reader2.read_var_bytes()
                    if len(pubkey) == 33:
                        d["Type"] = KeyType.ECDSA.name
                        d["Curve"] = Curve.P256.name
                        d["Value"] = pubkey.encode('hex')
                    else:
                        d["Type"] = KeyType.from_label(pubkey[0])
                        d["Curve"] = Curve.from_label(pubkey[1])
                        d["Value"] = pubkey.encode('hex')
                    pubKey_list.append(d)
                except Exception as e:
                    break
        attribute_list = []
        if len(attribute_bytes) != 0:
            ms = StreamManager.GetStream(attribute_bytes)
            reader2 = BinaryReader(ms)

            while True:
                try:
                    d = {}
                    key = reader2.read_var_bytes()
                    if len(key) == 0:
                        break
                    d["Key"] = str(key, 'utf-8')
                    d["Type"] = str(reader2.read_var_bytes(), 'utf-8')
                    d["Value"] = str(reader2.read_var_bytes(), 'utf-8')
                    attribute_list.append(d)
                except Exception as e:
                    break
        d2 = {}
        d2["Owners"] = pubKey_list
        d2["Attributes"] = attribute_list
        if len(recovery_bytes) != 0:
            addr = Address(recovery_bytes)
            d2["Recovery"] = addr.b58encode()
        d2["OntId"] = ont_id
        return d2
