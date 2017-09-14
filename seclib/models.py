

class Controller:

    def __init__(self,host,port, ssl=True, integrator=None, auth_token=None):
        self.endpoints = []
        self.auth_token = auth_token
        self.host = host
        self.port = port
        self.integrator = integrator
        self.ssl = ssl



class Endpoint:
    def __init__(self, host, os, raw=None):
        self.host = host
        self.os = os
        self.raw = raw