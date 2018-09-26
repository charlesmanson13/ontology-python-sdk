import json
from ontology.smart_contract.neo_contract.abi.struct_type import Struct


class Parameter(object):

    def __init__(self, name, type_value, value=None):
        """

        :param name:
        :type name: basestring
        :param type_value:
        :type type_value: basestring
        :param value:
        """
        self.name = name
        self.type = type_value
        self.value = value

    def set_value(self, obj):
        self.value = obj
