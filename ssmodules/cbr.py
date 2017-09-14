from seclib.integration_engine.http_integrator import Http_Integrator
###
#
# CARBON BLACK RESPONSE
# HTTP Integrator
#
###

class Module(Http_Integrator):

    def __init__(self):
        self.info = {
            'name': 'Carbon Black Response',
            'description': 'Carbon Black Response EDR'
        }

        self.discovery_conf = {
            'ports': ['443'],
            'regex': ['Cb Response', 'cb.min']
        }


        self.authentication_conf = {

            'requests':[
                {
                "request": """GET /api/auth HTTP/1.1
Host: example.com
Cache-Control: no-cache
                            """,
                "extractions": [r'"auth_token":\s+"(?P<__secs__auth_token>\w*)'],
                "auth": "HTTPDigestAuth"
                }
            ]
        }



        ##### Enumeration #####
        ## Custom extraction, returns a dict of vars
        # This is an enumeration extraction for carbon black, so we need to get
        # our special enum variables
        def enumeration_extraction(response, host, vars):
            rjson = response.json()
            vars['__secs__endpoints']=[]
            for endpoint in rjson:
                vend = {}
                vend['host'] = endpoint['computer_dns_name']
                vend['os'] = endpoint['os_environment_display_string']
                vend['id'] = endpoint['id']
                vend['raw'] = endpoint
                vars['__secs__endpoints'].append(vend)




        self.enumeration_conf = {
                'requests': [{
                    "request": """GET /api/v1/sensor HTTP/1.1
Host: 70.168.249.180
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
X-Auth-Token:__secs__auth_token
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8

        """,
                "custom_extraction": enumeration_extraction
            },
        ]
        }



        ##### Enumeration #####
        ## Custom extraction, returns a dict of vars
        # This is an enumeration extraction for carbon black, so we need to get
        # our special enum variables
        def smash_sessionid_extraction(response,host,vars):
            rjson = response.json()
            for session in rjson:
                if session['sensor_id'] == vars['__secs__endpoint_id'] and session['status'] != 'close':
                    vars['__secs__cbr_session_id'] = session['id']

        self.smash_conf = {
            "requests": [
                {
                'request':"""POST /api/v1/cblr/session HTTP/1.1
Host: 70.168.249.180
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
X-Auth-Token:__secs__auth_token
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8

{"sensor_id":__secs__endpoint_id}""",
                "sleep": 2,
            },
                {'request':"""GET /api/v1/cblr/session HTTP/1.1
Host: 70.168.249.180
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
X-Auth-Token:__secs__auth_token
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8

""",
    "retry_sleep": 5,
    "custom_extraction" : smash_sessionid_extraction,
    "required_vars": ['__secs__cbr_session_id']
          },
    {'request': """POST /api/v1/cblr/session/__secs__cbr_session_id/command HTTP/1.1
Host: 70.168.249.180
X-Auth-Token: __secs__auth_token
Content-Type: application/json
Cache-Control: no-cache

{
	"name": "create process",
	"object": "__secs__command"
}""",
                 "retry_sleep": 5,
                 "extractions": [r'"id":\s+(?P<__secs__cbr_command_id>\d*)'],
                 "required_vars": ['__secs__cbr_command_id'],
                 },
                {'request': """PUT /api/v1/cblr/session/__secs__cbr_session_id HTTP/1.1
Host: 70.168.249.180
X-Auth-Token: __secs__auth_token
Content-Type: application/json
Cache-Control: no-cache

{
    "sensor_id": "__secs__endpoint_id",
    "status": "close"
}""",
                 },
        ]
    }



        ## initialize HTTP integrator class
        super(Module, self).__init__(discovery_conf=self.discovery_conf, authentication_conf=self.authentication_conf,
                                     enumeration_conf=self.enumeration_conf, smash_conf=self.smash_conf,
                                     info=self.info)


