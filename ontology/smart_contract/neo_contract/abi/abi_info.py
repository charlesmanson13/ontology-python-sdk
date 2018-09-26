from ontology.smart_contract.neo_contract.abi.abi_function import AbiFunction


class AbiInfo(object):
    def __init__(self, hash_value='', entry_point='', functions=None, events=None):
        """
        
        :param hash_value:
        :type hash_value: basestring 
        :param entry_point: 
        :type entry_point: basestring
        :param functions: 
        :type functions: list
        :param events: 
        :type events: list
        """
        self.hash = hash_value
        self.entry_point = entry_point
        if functions is None:
            self.functions = list()
        else:
            self.functions = functions
        if events is None:
            self.events = list()
        else:
            self.events = events

    def get_function(self, name):
        """
        This interface is used to get an AbiFunction object from AbiInfo object by given function name.

        :param name: the function name in abi file
        :type name: basestring
        :return: AbiFunction | None if succeed, an AbiFunction will constructed based on given function name
        """
        for func in self.functions:
            if func['name'] == name:
                return AbiFunction(func['name'], func['returntype'], func['parameters'])
        return None
