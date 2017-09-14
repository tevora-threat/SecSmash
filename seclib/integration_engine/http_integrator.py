from integrator import Integrator
import re
import requests
from seclib.utils import multireplace, check_required_vars, extract_groupdict, extract_multi_groupdict
import time


from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.DEFAULT_SSL_CIPHER_LIST += 'HIGH:!DH:!aNULL'
except AttributeError:
    # no pyopenssl support used / needed / available
    pass

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        self.intpostvars = ''
        self.vars = {}
    @property
    def postvars(self):
        if self.intpostvars == '' and self.command not in ['GET','DELETE','HEAD']:
            self.intpostvars = self.rfile.read()
        return self.intpostvars

        self.rfile.readlines()
    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message




class Http_Integrator(Integrator):

    def __init__(self, discovery_conf, authentication_conf,
                 enumeration_conf, smash_conf, multi_endpoints=False, info=None):

        super(Http_Integrator, self).__init__(discovery_conf=discovery_conf, info=info)

        self.authentication_conf = authentication_conf
        self.enumeration_conf = enumeration_conf
        self.smash_conf = smash_conf
        self.authentication_token = None


    def send_request_text_to_host(self, host, request_text, auth):
        http_request = HTTPRequest(request_text)

        if host.ssl:
            urlprefix = 'https://'
        else:
            urlprefix = 'https://'

        url = urlprefix + host.host + ":" +host.port + http_request.path
        headers = http_request.headers.dict
        headers['host'] =host.host

        proxies = None
        # for testing
        #proxies = {
        #    'http': 'http://127.0.0.1:8080',
        #    'https': 'http://127.0.0.1:8080',
        #}
        timeout = 600
        if http_request.command not in ['POST','PUT','PATCH']:
            return requests.request(http_request.command, url,headers=headers, auth=auth, verify=False, allow_redirects=False, proxies=proxies, timeout=timeout)
        else:
            payload = http_request.postvars
            return requests.request(http_request.command,url, data=payload, headers = headers, auth=auth, verify=False,allow_redirects=False, proxies=proxies,timeout=timeout)


    def run_request(self, request, host, credential, vars):
        if 'custom_request' in request:
            response = request['custom_request'](host, vars, credential)
        else:
            assert 'request' in request

            if "auth" in request:
                assert credential is not None
                if request['auth'] == 'HTTPDigestAuth':
                    auth = requests.auth.HTTPDigestAuth(credential['username'], credential['password'])
                elif request['auth'] == 'HTTPBasicAuth':
                    auth = requests.auth.HTTPBasicAuth(credential['username'], credential['password'])
            else:
                auth = None
            if credential:
                vars['__secs__username'] = credential['username']
                vars['__secs__password'] = credential['password']
            if host.auth_token:
                vars['__secs__auth_token'] = host.auth_token


            if vars != {}:
                request_text = multireplace(request, vars)
            else:
                request_text = request["request"]
            response = self.send_request_text_to_host(host, request_text, auth)
        assert response is not None
        if 'extractions' in request:
            extractions = request['extractions']
            for extraction in extractions:
                groupdict =  extract_groupdict(response.text,extraction)
                if groupdict:
                    vars.update(groupdict)
        if 'multi_extraction' in request:
            for multivar, extraction in request['multi_extraction'].iteritems():
                groupdicts=extract_multi_groupdict(response.text, extraction)
                if groupdicts:
                    vars[multivar] = groupdicts

        if 'header_extraction' in request:
            for key, value in request['header_extraction'].iteritems():
                if key in response.headers:
                    text= response.headers[key]
                    groupdict = extract_groupdict(text,value)
                    if groupdict:
                        vars.update(groupdict)

        if 'cookie_extraction' in request:
            for key, value in request['cookie_extraction'].iteritems():
                if key in response.cookies:
                    vars[value] = response.cookies[key]


        if 'custom_extraction' in request:
            request['custom_extraction'](response,vars=vars,host=host)

        if 'sleep' in request:
            time.sleep(request['sleep'])

    def run_request_chain(self, conf, host, credential=None, vars={}):
        vars['__secs__host'] = host.host

        for request in conf['requests']:
            self.run_request(request=request, host=host, credential=credential, vars=vars)

            if 'required_vars' in request:
                required_vars = request['required_vars']

                if not check_required_vars(vars=vars,required_vars=required_vars):
                    if 'retries' in request:
                        retries = request['retries']
                    else:
                        retries = 3
                    if 'retry_sleep' in request:
                        sleep = request['retry_sleep']
                    else:
                        sleep = 3
                    tried = 1
                    while tried < 3 and not check_required_vars(vars=vars,required_vars=required_vars):
                        time.sleep(sleep)
                        self.run_request(request=request, host=host, credential=credential, vars=vars)
                        for var in required_vars:
                            if var in vars:
                                break
                        tried +=1
        return vars


    def authenticate(self, host, credential=None):
        vars = self.run_request_chain(self.authentication_conf, host, credential)
        if '__secs__auth_token' in vars:
            host.auth_token = vars['__secs__auth_token']
            print "authtoken: " + host.auth_token
            return True
        else:
            return False

    def enumerate(self, host, credential=None):
        vars = self.run_request_chain(conf=self.enumeration_conf, host = host, credential=credential)
        endpoints = vars['__secs__endpoints']
        host.endpoints.extend(endpoints)
        return endpoints


    def smash(self, host,command, endpoint_list=None, credential=None):
        if endpoint_list:
            ## https://stackoverflow.com/questions/29051573/python-filter-list-of-dictionaries-based-on-key-value
            endpoints = [d for d in host.endpoints if d['host'] in endpoint_list]
        else:
            endpoints = host.endpoints

        results = {}
        for endpoint in endpoints:
            vars = {}
            vars['__secs__command'] = command
            vars['__secs__endpoint_os'] = endpoint['os']
            vars['__secs__endpoint_id'] = endpoint['id']
            vars['__secs__endpoint_host'] = endpoint['host']
            try:
                self.run_request_chain(conf=self.smash_conf, host = host, credential=credential, vars=vars)
            except:
                pass
            if '__secs__command_result' in vars:
                results[endpoint['id']] = vars['__secs__command_results']


