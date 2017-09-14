#!/usr/bin/env python

from colorama import Fore, Style

class Validate():
    def __init__(self, options):
        self.options = options

    def validate_required(self):
        # Check if required values are set

        for option, values in self.options.iteritems():
            if values['required'] == 'True' and ((not values['value']) or (values['value'] == '')):
                print (Fore.RED + Style.BRIGHT + "Required options not set!\n" + Style.RESET_ALL)
                return False
            else:
                return True

    def validate_switch(self):
        # Make sure switch is set to True or False

        for option, values in self.options.iteritems():
            if values['description'].startswith('True/False:') and ((not values['value']) or (values['value'] == '') or (values['value'].lower() != 'true') or (values['value'].lower() != 'false')):
                print (Fore.RED + Style.BRIGHT + "Value must be set to true or false!\n" + Style.RESET_ALL)
                return False
            else:
                return True

    def validate_module(self, mainmenu, modulename):
        # Make sure module exists
        if modulename == '' or modulename.lower() == 'all':
            return True
        if modulename not in mainmenu.modules.modules:
            print (Fore.RED + Style.BRIGHT + "Invalid Module!\n" + Style.RESET_ALL)
        else:
            return True

    def validate_port(self, port):
        # Make sure port is valid
        if port == '':
            return True
        try:
            if int(port) < 1 or int(port) > 65535:
                print (Fore.RED + Style.BRIGHT + "Invalid port number\n" + Style.RESET_ALL)
                return False
        except ValueError:
            print (Fore.RED + Style.BRIGHT + "Invalid port number\n" + Style.RESET_ALL)
            return False

    #def validate_target(self):
    #   for option, values in self.options.iteritems():
    #      if options['subnet']
