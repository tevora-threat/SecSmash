#!/usr/bin/env python


import os
import time

from cmd import Cmd
from colorama import Fore, Style

from seclib import discovery
from seclib import modulehandler
from seclib import models
from seclib import sslib
import pprint

class SSMenu(Cmd):

    #for some reason this breaks invalid commands
    #nohelp = "Invalid help"

    def __init__(self, mainmenu):
        Cmd.__init__(self)
        self.doc_header = 'Commands'
        self.do_help.__func__.__doc__ = """\tDisplays the help menu\n"""
        self.mainmenu = mainmenu

    def do_back(self, args):
        """\tGo back\n"""
        return True

    def do_execute(self, args):
        """\tExecute discovery\n """
        print "Work In Progress EXECUTE"

    def do_run(self, args):
        """\tRun discovery\n"""
        print "Work In Progress RUN"


    def do_options(self, args):
        """\tView available options\n"""
        headers = ['Name', 'Required', 'Value', 'Description']
        print "\nDescription: {}".format(self.description)
        print "\n"
        print "{:13} {:13} {:20} {}".format(headers[0], headers[1], headers[2], headers[3])
        print "-" * 90

        for keys, values in self.options.iteritems():
            #if len(values['value']) > 18:

            print "{:13} {:<13} {:<20} {}".format(keys, values['required'], values['value'][0:20], values['description'])
        print "\n"

    def do_set(self, line):
        """\tSet Values for module\n"""

        if line <= 1:
            print "Invalid"
        else:
            arglist = line.split(' ')
            if arglist[0].lower() in self.options and len(arglist) > 1:
                setvalue = arglist[0]
                self.options[setvalue]['value'] = ' '.join(arglist[1:])
            else:
                print (Fore.RED + Style.BRIGHT + "Invalid value")
                print(Style.RESET_ALL)

    def complete_set(self, text, line, begidx, endidx):
        if not text:
            completed = self.options[:]
        else:
            completed = [ f
                            for f in self.options
                            if f.startswith(text)
                            ]
        return completed


    def do_main(self, line):
        "Go back to the main menu."
        raise GoMain()

    def do_discovery(self, line):
        "Jump to the Discovery menu."
        raise GoDiscovery()

    def do_enumerate(self, line):
        "Jump to the Discovery menu."
        raise GoEnumerate()

    def do_smash(self, line):
        "Jump to the Discovery menu."
        raise GoSmash()

    def do_exit(self, args):
        """\tExit the program\n"""
        print "Exiting..."
        raise SystemExit

class GoMain(Exception):
    pass
class GoDiscovery(Exception):
    pass
class GoEnumerate(Exception):
    pass
class GoSmash(Exception):
    pass


class MainMenu(Cmd):

    #nohelp = "Invalid help"
    listops = ['modules', 'securityproducts', 'hosts', 'endpoints', 'controllers', 'endpoints']
    useops = ['discovery', 'enumerate', 'creds', 'smash', 'configurec2', 'autosmash']

    def __init__(self):
        Cmd.__init__(self)
        self.doc_header = "Commands"
        self.prompt = (Fore.BLUE + Style.BRIGHT + 'SecSmash > ' + Style.RESET_ALL)

        self.modules = modulehandler.ModuleHandler()
        self.target = ''
        self.username = ''
        self.password = ''
        self.module = ''
        self.payload =''
        self.hosts = []
        self.menu_state = 'Main'
        self.do_help.__func__.__doc__ = """\tDisplays the help menu\n"""

    def cmdloop(self, line):
        """
        The main cmdloop logic that handles navigation to other menus.
        """
        while True:
            try:
                if self.menu_state == 'Discovery':
                    self.do_discovery('')
                elif self.menu_state == 'Enumerate':
                    self.do_enumerate('')
                elif self.menu_state == 'Smash':
                    self.do_smash('')
                else:
                    Cmd.cmdloop(self)

            except GoMain as e:
                self.menu_state = 'Main'

            except GoDiscovery as e:
                self.menu_state = 'Discovery'

            except GoEnumerate as e:
                self.menu_state = 'Enumerate'

            except GoSmash as e:
                self.menu_state = 'Smash'

    def get_controller_names(self):
        names = []
        for controller in self.hosts:
            names.append(controller.host)

    def listmodules(self):
        attackmodules = []
        for i in os.listdir('./ssmodules'):
            if i.startswith("__init__") or i.endswith(".pyc"):
                continue
            else:
                attackmodules.append(os.path.splitext(i)[0])

        print (Fore.GREEN + Style.BRIGHT + "\t{} Modules available".format(len(attackmodules)))
        print(Style.RESET_ALL)

    def do_discovery(self, args):
        """\tDiscovery of controllers on network\n"""
        discoverymenu = DiscoveryMenu(self)
        discoverymenu.cmdloop('')

    def do_enumerate(self, args):
        """\tEnumerate a discovered controller for information\n"""
        enumeratemenu = EnumerateMenu(self)
        enumeratemenu.cmdloop('')

    def do_smash(self, args):
        """\tPwn Controllers\n"""
        smashmenu = SmashMenu(self)
        smashmenu.cmdloop('')

    def do_creds(self, args):
        """\tCredential manager - Work In Progress\n"""
        credmenu = CredsMenu()
        credmenu.cmdloop('')

    def do_configurec2(self, args):
        """\tConfigure C2 Information - Work in Progress\n"""
        c2menu = C2Menu()
        c2menu.cmdloop('')

    def do_autosmash(self, args):
        """\tDiscovery, enumeration, payload execution automatically\n"""
        automenu = AutoSmashMenu()
        automenu.cmdloop('')

    def do_use(self, args):
        "\tUse an attack type\n"

        if args == 0:
            print "Invalid"
        else:
            usedict = args.split(' ')
            if usedict[0].lower() in self.useops:
                if usedict[0].lower() == "discovery":
                    self.do_discovery('')
                elif usedict[0].lower() == "enumerate":
                    self.do_enumerate('')
                elif usedict[0].lower() == "creds":
                    self.do_creds('')
                elif usedict[0].lower() == "smash":
                    self.do_smash('')
                elif usedict[0].lower() == "configurec2":
                    self.do_configurec2('')
                elif usedict[0].lower() == "autosmash":
                    self.do_autosmash('')

            elif usedict[0].lower() not in self.useops:
                print "Invalid use command"

    def complete_use(self, text, line, begidx, endidx):
        if not text:
            completed = self.useops[:]
        else:
            completed = [ f
                            for f in self.useops
                            if f.startswith(text)
                            ]
        return completed


    def do_help(self, *args):
        """\tDisplays the help menu\n"""
        Cmd.do_help(self, *args)

    def do_options(self, line):
        """\tDisplays the help menu\n"""
        Cmd.do_help(self, line)

    def do_list(self, args):
        """\tLists information in secsmash\n \tList options: \n\t\t-modules \n\t\t-controllers \n\t\t-endpoints\n"""

        if args == 'modules':
            modules = []
            for i in os.listdir('./ssmodules'):
                if i.startswith("__init__") or i.endswith(".pyc"):
                    continue
                else:
                    modules.append(os.path.splitext(i)[0])
            num = 1
            print (Fore.GREEN + Style.BRIGHT + "\n\tAvailable Modules:\n")
            for x in modules:
                print "\t{}. {}".format(num, x)
                num = num + 1
            print(Style.RESET_ALL)

        elif args == 'creds':
            print "\tno creds yet"
        elif args == 'controllers':
            print "Show controllers\n"
        elif args == 'endpoints':
            print "Show endpoints\n"
        else:
            print "plz dont"

    def complete_list(self, text, line, begidx, endidx):
        if not text:
            completed = self.listops[:]
        else:
            completed = [ f
                            for f in self.listops
                            if f.startswith(text)
                            ]
        return completed

    def do_exit(self, args):
        """\tExit the program\n"""
        print "Exiting...\n"
        raise SystemExit


class DiscoveryMenu(SSMenu):

    def __init__(self, mainmenu):
        Cmd.__init__(self)
        self.doc_header = "Commands"
        self.prompt = (Fore.BLUE + Style.BRIGHT + 'SS/Discovery > ' + Style.RESET_ALL)
        self.description = "Discover targets on a specified network"
        self.mainmenu = mainmenu

        self.options = {'subnet': {
                            'required': 'True',
                            'value': '',
                            'description': 'Subnet to discover sec products on, use CIDR or single IP',
                            },
                        'module': {
                            'required': 'False',
                            'value': '',
                            'description': 'Specify specific sec prods to look for, Default is set to all',
                            },
                        'port': {
                            'required': 'False',
                            'value': '',
                            'description': 'Specify ports not found in modules'
                            },
                        'moduleports': {
                            'required': 'True',
                            'value': 'true',
                            'description': 'True/False: Use ports specified in modules'
                            }
                        }
        self.validate = sslib.Validate(self.options)

    def do_run(self, line):
        """\tRun discovery\n"""
        self.rundiscovery()


    def do_execute(self, line):
        '''\tExecute discovery'''
        self.rundiscovery()


    def rundiscovery(self):
        if not self.validate.validate_required():
            return
        if not self.validate.validate_switch():
            #this doesnt work right now
            return
        if not self.validate.validate_port(self.options.get('port')['value']):
            return

        modulename = self.options.get('module')['value']

        if not self.validate.validate_module(self.mainmenu, modulename):
            return

        subnet = self.options.get('subnet')['value']

        module = self.mainmenu.modules.modules
        ports = self.options.get('port')['value']
        moduleports = self.options.get('moduleports')['value']


        print (Fore.GREEN + Style.BRIGHT + "Discovering controllers!\n" + Style.RESET_ALL)
        do_discovery = discovery.Discovery(subnet, modulename, module, ports, moduleports)


class EnumerateMenu(SSMenu):
    def __init__(self, mainmenu):
        Cmd.__init__(self)
        self.prompt = (Fore.BLUE + Style.BRIGHT + 'SS/Enumerate > ' + Style.RESET_ALL)
        self.description = "Login and Enumerate information from known controller"
        self.mainmenu = mainmenu
        self.options = {'module': {
                            'required': 'True',
                            'value': '',
                            'description': 'Module to use against target',
                            },
                        'username': {
                            'required': 'False',
                            'value': '',
                            'description': 'Username to authenticate with',
                            },
                        'password': {
                            'required': 'True',
                            'value': '',
                            'description': 'Corresponding password to username OR API Token',
                            },
                        'target': {
                            'required': 'True',
                            'value': '',
                            'description': 'Controller to enumerate',
                            },
                        'port': {
                            'required': 'False',
                            'value': '',
                            'description': 'Override module port',
                            }
                        }

    def do_run(self, line):
        """\tRun Enumeration\n"""
        self.runenumeration()


    def do_execute(self, line):
        """\tExecute Enumeration\n"""
        self.runenumeration()


    def runenumeration(self):
        modulename = self.options.get('module')['value']
        self.mainmenu.module = modulename
        module = self.mainmenu.modules.modules[modulename]
        credential = {
            'username': self.options.get('username')['value'],
            'password': self.options.get('password')['value']
        }

        self.mainmenu.username = credential['username']
        self.mainmenu.password = credential['password']

        target = self.options.get('target')['value']
        self.mainmenu.target = target
        port = self.options.get('port')['value']

        host = None
        for h in self.mainmenu.hosts:
            if target == h.host:
                host = h
        if not host:
            host = models.Controller(host=target, port=port, ssl=True, integrator=module)
            self.mainmenu.hosts.append(host)

        print (Fore.GREEN + Style.BRIGHT +"Enumerating controller!\n" + Style.RESET_ALL)
        module.authenticate(host=host, credential=credential)
        pp = pprint.PrettyPrinter(indent=4)

        pp.pprint(module.enumerate(host))


class SmashMenu(SSMenu):
    def __init__(self, mainmenu):
        Cmd.__init__(self)
        self.prompt = (Fore.BLUE + Style.BRIGHT + 'SS/Smash > ' + Style.RESET_ALL)
        self.description = "Execute payload against targets"
        self.mainmenu = mainmenu

        self.options = {'module': {
                            'required': 'True',
                            'value': self.mainmenu.module,
                            'description': 'Module to run for selected target',
                            },
                        'username': {
                            'required': 'False',
                            'value': self.mainmenu.username,
                            'description': 'Username to authenticate to tool',
                            },
                        'password': {
                            'required': 'False',
                            'value': self.mainmenu.password,
                            'description': 'Password to authenticate to tool OR API Token',
                            },
                        'target': {
                            'required': 'True',
                            'value': self.mainmenu.target,
                            'description': 'Host to execute payload against',
                            },
                        'endpoint': {
                            'required': 'False',
                            'value': '',
                            'description': 'Host to execute payload against',
                        },
                        'payload': {
                            'required': 'True',
                            'value': self.mainmenu.payload,
                            'description': 'Command to execute against connected agents',
                            }
                        }

    def do_run(self, line):
        """\tRun Smash\n"""
        self.runsmash()

    def do_execute(self, line):
        """\tExecute Smash\n"""
        self.runsmash()

    def complete_target(self,text,line,begidx,endidx):
        names = self.mainmenu.get_controller_names()
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]

    def runsmash(self):
        modulename = self.options.get('module')['value']
        module = self.mainmenu.modules.modules[modulename]


        hostname = self.options.get('target')['value']
        host = None
        for h in self.mainmenu.hosts:
            if h.host == hostname:
                host = h

        if not host:
            print "you have to enumerate first"
            return
        self.mainmenu.payload = self.options.get('payload')['value']
        print (Fore.GREEN + Style.BRIGHT + "Smashing controllers!\n" + Style.RESET_ALL)
        endpoint = self.options.get('endpoint')['value']
        if endpoint == '':
            endpoint = None
        module.smash(host = host,
                command = self.options.get('payload')['value'],
                endpoint_list = [endpoint],
        )


class CredsMenu(SSMenu):
    def __init__(self):
        Cmd.__init__(self)
        self.prompt = (Fore.BLUE + Style.BRIGHT + 'SS/Creds > ' + Style.RESET_ALL)
        self.description = "Credential manager"

        self.options = {'username': {
                            'required': 'True',
                            'value': '',
                            'description': 'Add, delete or modify username',
                            },
                        'password': {
                            'required': 'True',
                            'value': '',
                            'description': 'Add, delete or modify password',
                            },
                        'secprod': {
                            'required': 'True',
                            'value': '',
                            'description': 'Security product where credentials are valid',
                            },
                        'target': {
                            'required': 'True',
                            'value': '',
                            'description': 'Target where credentials are valid',
                            },
                        'apikey': {
                            'required': 'False',
                            'value': '',
                            'description': 'API key instead of credentials',
                            }
                        }


class C2Menu(SSMenu):
    def __init__(self):
        Cmd.__init__(self)
        self.prompt = (Fore.BLUE + Style.BRIGHT + 'SS/C2 > ' + Style.RESET_ALL)
        self.description = "Configure payloads for Command and Control"

        self.options = {'serverip': {
                            'required': 'True',
                            'value': '',
                            'description': 'C2 server IP address',
                            },
                        'serverport': {
                            'required': 'True',
                            'value': '',
                            'description': 'C2 server port',
                            },
                        'resttoken': {
                            'required': 'True',
                            'value': '',
                            'description': 'Rest token for authentication',
                            }
                        }


class AutoSmashMenu(SSMenu):
    def __init__(self):
        Cmd.__init__(self)
        self.prompt = (Fore.BLUE + Style.BRIGHT + 'SS/AutoSmash > ' + Style.RESET_ALL)
        self.description = "Discover and automatically execute payloads"

        self.options = {'subnet': {
                            'required': 'True',
                            'value': '',
                            'description': 'Subnet to run discovery against',
                            },
                        'payload': {
                            'required': 'True',
                            'value': '',
                            'description': 'Payload to execute on target',
                            },
                        'username': {
                            'required': 'False',
                            'value': '',
                            'description': 'Username to authenticate with for discovered target',
                            },
                        'password': {
                            'required': 'True',
                            'value': '',
                            'description': 'Username to authenticate with for discovered target OR API Token',
                            }
                        }


def banner():
    print "\n"
    print (Fore.GREEN + Style.NORMAL + """
---------------------------------------------------------------------
|   _____                _____                                __    |
|  / ___/  ___   _____  / ___/   ____ ___   ____ _   _____   / /_   |
|  \__ \  / _ \ / ___/  \__ \   / __ `__ \ / __ `/  / ___/  / __ \\  |
| ___/ / /  __// /__   ___/ /  / / / / / // /_/ /  (__  )  / / / /  |
|/____/  \___/ \___/  /____/  /_/ /_/ /_/ \__,_/  /____/  /_/ /_/   |                                                      
---------------------------------------------------------------------
|                 Pwning enterprise security tools                  |
---------------------------------------------------------------------
|                       v1.0      By: KD & SF                       |
---------------------------------------------------------------------""")
    print(Style.RESET_ALL)


def main():
    os.system('clear')
    banner()
    prompt = MainMenu()
    prompt.listmodules()
    time.sleep(0.5)
    prompt.cmdloop('')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\nExiting!\n"
