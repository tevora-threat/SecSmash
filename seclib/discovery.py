#!/usr/bin/env python

from lxml import html
import requests

from colorama import Fore, Style
from netaddr import IPNetwork
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.DEFAULT_SSL_CIPHER_LIST += 'HIGH:!DH:!aNULL'
except AttributeError:
    # no pyopenssl support used / needed / available
    pass

class Discovery:
    def __init__(self, targets, modulename, module, ports=None, module_ports=False):
        self.targets = targets
        self.ports = ports
        self.module_ports = module_ports
        self.modulename = modulename
        self.module = module
        self.modules = {}

        self.discovery_values = self.get_discoveryvalues(self.modulename, self.module)
        self.app_discovery(self.discovery_values)

    def app_discovery(self, discovery_values):

        iplist = []
        if '/' in self.targets:
            for ip in IPNetwork(self.targets):
                iplist.append(ip)
        elif '-' in self.targets:
            print 'This isnt implemented yet'
            return
        else:
            iplist.append(self.targets)

        headers = ({
                "User-Agent": "Mozilla/5.0 (Windows NT 5.1; 32bit; rv:10.0) Gecko/20100301 Firefox/10.0)"
                })

        try:
            n = 0
            for port in discovery_values['portlist']:
                p = port[n]
                n = + 1
                for ip in iplist:
                    target = 'https://{}:{}'.format(ip, p)
                    try:
                        page = requests.get(target, timeout=2, headers=headers, verify=False)

                        # print page.content
                        discdict = discovery_values['regexdict']
                        for key in discdict:
                            for check in discdict[key]:
                                if check in page.content:
                                    print "{} Discovered at {}\n".format(key, ip)
                                    if len(iplist) > 1:
                                        cont = raw_input("Continue discovery? (y/n): ")
                                        if cont.lower() == 'no' or cont.lower() == 'n':
                                            return
                                        else:
                                            continue
                                    else:
                                        return
                        else:
                            print (Fore.GREEN + Style.BRIGHT + "No controllers discovered\n" + Style.RESET_ALL)

                    except requests.exceptions.ConnectionError as e:
                        #print "{} Not listening\n".format(ip)
                        print e
                        continue

                    except requests.exceptions.InvalidURL:
                        print "Invalid URL\n"
        except KeyboardInterrupt:
            return


        #tree = html.fromstring(page.content)

        #print tree[1]
        #desc = tree.xpath('//*[@title="Cb Response"]')

        #print desc


    def get_discoveryvalues(self, modulename, module):

        namelist = []
        portlist = []
        regexdict = {}

        #get port and regex information
        if modulename == '' or modulename.lower() == 'all':
            for names in module:
                namelist.append(names)

            for n in namelist:
                if module[n].discovery_conf.get('ports') in portlist:
                    continue
                else:
                    portlist.append(module[n].discovery_conf.get('ports'))

            for names in module:
                regexdict.update({names: module[names].discovery_conf.get('regex')})

        else:
            namelist.append(modulename)
            for n in namelist:
                portlist.append(module[n].discovery_conf.get('ports'))

            for names in namelist:
                regexdict.update({names: module[names].discovery_conf.get('regex')})

        return {'portlist': portlist,
                'regexdict': regexdict}
