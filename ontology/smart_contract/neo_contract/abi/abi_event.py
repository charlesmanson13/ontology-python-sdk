
class AbiEvent(object):
    def __init__(self, name, return_type, parameters):
        """

        :param name:
        :type name: basestring
        :param return_type:
        :type return_type: basestring
        :param parameters:
        :type parameters: list
        """
        self.name = name
        self.return_type = return_type
        self.parameters = parameters

    def get_parameters(self):
        return self.parameters

    def set_params_value(self, *objs):
        if len(self.parameters) != len(objs):
            raise Exception("param error")
        for i in range(len(objs)):
            self.parameters[i].set_value(objs[i])

