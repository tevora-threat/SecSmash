from abc import ABCMeta,abstractmethod, abstractproperty


class Credential(object):
    def __init__(self,  password, type, username=None,):
        self.password = password
        self.type = type
        self.username = username


class Integrator(object):
    __metaclass__ = ABCMeta

    def __init__(self, discovery_conf, info=None):
        self.info = info
        self.discovery_conf = discovery_conf
        self.range = range

    @abstractmethod
    def authenticate(self):
        raise NotImplementedError("Integrators must implement an authenticator method to use this class")

    @abstractmethod
    def enumerate(selfs):
        raise NotImplementedError("Integrators must implement an enumerator")

    @abstractmethod
    def smash(self, command):
        raise NotImplementedError("Integrators must implement an execution engine")

    @property
    def get_discovery_dict(self):
        return self.discovery_conf

    @property
    def get_endpoints(self):
        return self.endpoints


