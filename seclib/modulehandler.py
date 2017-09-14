#!/usr/bin/env python

import fnmatch
import os
import imp
from seclib.integration_engine.integrator import  Integrator

class ModuleHandler():

    def __init__(self):

        self.modules = {}
        self.load_modules()

    def load_modules(self):

        #Debugging
        print "Loading modules...\n"
        instpath = './ssmodules'
        pattern = '*.py'


        for root, dirs, files in os.walk(instpath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)
                if fnmatch.fnmatch(filename, '__init__.py'):
                    continue
                modulename = filePath.split(instpath)[-1][1:-3]

                module = imp.load_source(modulename, filePath).Module()
                if isinstance(module,Integrator):
                    self.modules[modulename] = module

                #print self.modules[modulename].info