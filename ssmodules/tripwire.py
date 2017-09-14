###
#
# TRIPWIRE
#
###
import seclib.utils
from seclib.integration_engine.http_integrator import Http_Integrator
import collections
import urllib


class Module(Http_Integrator):
    def __init__(self):
        self.info = {
            'name': 'Tripwire Enterprise',
            'description': 'Tripwire Security'
        }

        self.discovery_conf = {
            'ports': '443',
            'regex': ['console/app.showApp.cmd']
        }


        ## Custom extractor for both session cookies
        # Maybe we should handle in the template somehow
        def trip_auth_extraction(response, host, vars):
            jsessionid = response.cookies['JSESSIONID']
            ssojsessionid = response.cookies['JSESSIONIDSSO']

            auth_token = "JSESSIONID=" + jsessionid + "; JSESSIONIDSSO=" + ssojsessionid + ";"
            vars['__secs__auth_token'] = auth_token


        self.authentication_conf = {

            'requests': [
                {
                    "request":"""GET /console/app.showApp.cmd HTTP/1.1
host:__secs__host
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8

""",
                    "cookie_extraction": {'JSESSIONID':'__secs__auth_token'},
                    "sleep": 4
                },
                {"request": """POST /console/j_security_check HTTP/1.1
Host: __secs__host
Connection: close
Content-Length: 77
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en_US; JSESSIONID=__secs__auth_token

loginCompId=2&j_username=__secs__username&j_password=__secs__password&locale=en_US""",
                 },
                {
                    "request":"""GET /console/app.showHome.cmd HTTP/1.1
Host: __secs__host
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://__secs__host/console/app.showApp.cmd
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; JSESSIONID=__secs__auth_token; localeId=en_US

""",
                    "cookie_extraction": {'JSESSIONID':'__secs__auth_token'},
                },

            ]
        }


        def tripwire_node_enumeration(response,host,vars):
            vars['__secs__endpoints'] =[]
            def extract_nested_nodes(nested):
                if isinstance(nested,list):
                    for node in nested:
                        if isinstance(node, collections.Mapping):
                            if 'id' in node and 'nodeName' in node:
                                endpoint = {
                                    'host': node['nodeName'],
                                    'id': node['id']
                                }
                                vars['__secs__endpoints'].append(endpoint)
                            if 'children' in node:
                                if isinstance(nested, node['children']):
                                    extract_nested_nodes(node['children'])

            nodes = response.json
            extract_nested_nodes(nodes)


        self.enumeration_conf = {
                "requests":
            [
                {"request": """GET /csrf HTTP/1.1
Host: __secs__host
Connection: close
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: */*
Referer: https://__secs__host/console/app.showHome.cmd
Accept-Language: en-US,en;q=0.8
Cookie: localeId=en_US; JSESSIONID=__secs__auth_token;

        """,
                 "extractions": [r'"CSRF_TOKEN", "(?P<__secs__csrf_token>.*)"'],
                 },
                {"request": """POST /console/app.search.cmd?controllerId=2343 HTTP/1.1
Host: __secs__host
Connection: close
Content-Length: 980
Cache-Control: max-age=0
Origin: https://__secs__host
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://__secs__host/console/app.showComp.cmd?Id=2346
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en_US; JSESSIONID=__secs__auth_token

action=saveAndSearch&criteria.searchExecuted=true&pageNum=1&selectedSearchType=objectType.si.genericServerNode&CSRF_TOKEN=__secs__csrf_token&search.node.name.op=3&sev_796=&search.serverNode.remoteHost.op=3&sev_797=&search.node.make.op=3&sev_798=&search.node.model.op=3&sev_799=&search.node.version.op=3&sev_800=&search.node.description.op=3&sev_801=&search.node.changeTime.endDate=&search.node.changeTime.isRelative=&search.node.changeTime.startDate=&search.node.changeTime.currentTime=1500959535327&sev_881=1500952843141_ANY_1500952843141&sev_882=1500952843141_ANY_1500952843141&search.node.elementName.op=3&sev_883=&sev_885=&search.node.severityRange.minValue=0&search.node.severityRange.maxValue=10000&search.serverNode.lastRegistrationTime.startDate=&search.serverNode.lastRegistrationTime.isRelative=&search.serverNode.lastRegistrationTime.currentTime=1500959535617&search.serverNode.lastRegistrationTime.endDate=&search.node.agentVersion.op=3&sev_10910=""",
                 "multi_extraction": {'__secs__endpoints':r'NAME="oid" VALUE="(?P<id>.*:.*)" TYPE[\S\s].*?middle">(?P<host>[^<]*?)<\/A>\s*<\/TD>\s*<TD CLASS.*NOWRAP>(?P<os>.*)<\/TD>'},
                 },

            ]
        }

        self.smash_conf = {
                "requests": [

                    {"request": """GET /csrf HTTP/1.1
Host: __secs__host
Connection: close
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: */*
Referer: https://__secs__host/console/app.showHome.cmd
Accept-Language: en-US,en;q=0.8
Cookie: localeId=en_US; JSESSIONID=__secs__auth_token;

        """,
                 "extractions": [r'"CSRF_TOKEN", "(?P<__secs__csrf_token>.*)"'],
                 },
                             {'request':"""POST /ajaxRequest/methodCall.do HTTP/1.1
Host: __secs__host
Connection: close
Content-Length: 348
CSRF_TOKEN: __secs__csrf_token
Origin: https://10.0.101.143
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest, Tripwire
Accept: */*
Accept-Language: en-US,en;q=0.8
Cookie: localeId=en; JSESSIONID=__secs__auth_token

Id=2629&m_arguments=%7B%22isPreload%22%3A%20true%2C%20%22treePath%22%3A%20%22%3Broot%22%2C%20%22treeId%22%3A%202629%7D&m_use_xjson_response_header=false&m_convert_result_to_json=false&m_target_class_name=com.tripwire.space.ui.web.appevolved.extjs.tree.AjaxTreeNodeLoader&m_target_method_name=loadTreeNode&m_IECachePrevention=1500973312821&node=root""",
                              "extractions": [r'"id":"(?P<__secs__rule_root>.*?)"'],

                              },
                    {'request':"""GET /console/app.showComp.cmd?Id=2688&urlModifier=82&dlgCtxId=-9223372036854775806&identifier=9499 HTTP/1.1
Host: __secs__host
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://__secs__host/console/app.showComp.cmd?Id=2689&treePath=agent%3B9499&urlModifier=82&dlgCtxId=-9223372036854775806
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en; JSESSIONID=__secs__auth_token"""},
                    {'request':"""POST /console/app.showWizard.cmd?wizardName=wizard.newCommandExecutionRule&wndName=Wizard:wizard.newCommandExecutionRule HTTP/1.1
Connection: close
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
origin: https://__secs__host
Content-Length: 151
accept-language: en-US,en;q=0.8
upgrade-insecure-requests: 1
host: __secs__host
referer: https://10.0.101.143/plugins/console/vessel.jsp?idx=1
cache-control: max-age=0
cookie: testForCookies=success; localeId=en; JSESSIONID=__secs__auth_token
content-type: application/x-www-form-urlencoded

commandId=wizard.newCommandExecutionRule.showCmd&parentGroup=__secs__rule_root&CSRF_TOKEN=__secs__csrf_token"""},



                             {
                    'request':"""POST /console/app.finishWizard.cmd HTTP/1.1
Host: __secs__host
Connection: close
Content-Length: 581
Cache-Control: max-age=0
Origin: https://__secs__host
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://__secs__host/console/app.showComp.cmd?Id=9490&urlModifier=365&dlgCtxId=-9223372036854775783&wndName=Wizard%3Awizard.newCommandExecutionRule&parentGroup=-__secs__rule_root&cancelAvailable=true&nextAvailable=true&backAvailable=true&finishAvailable=true
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en_US; JSESSIONID=__secs__auth_token

wizardId=9489&dlgCtxId=-9223372036854775805&wndName=Wizard%3Awizard.newCommandExecutionRule&parentGroup=__secs__rule_root&wizardName=wizard.newCommandExecutionRule&CSRF_TOKEN=__secs__csrf_token&commandId=wizard.newCommandExecutionRule.showCmd&ObjModelVal_Severity=10000&ObjModelVal_IdTracked=true&ObjModelVal_TimeoutInMinutes=15&ObjModelVal_Name=__secs__trip_rule&ObjModelVal_Description=just+a+regular+rule+in+the+neighborhood+&ObjModelVal_ElementName=__secs__trip_rule&ObjModelVal_CommandLine=__secs__command&ObjModelVal_ExcludePattern=&ObjModelVal_ReplaceString=&cmdId=9493"""
                    },
                    {'request':"""GET /console/app.showComp.cmd?Id=2303 HTTP/1.1
Host: __secs__host
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://__secs__host/console/con.showTool.cmd
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en; JSESSIONID=__secs__auth_token

""",
                     'sleep':5},

                    {"request": """GET /console/app.showComp.cmd?Id=2637&sortColumn=1&sortIsAscending=false&pageNum=1&urlModifier=34%2C35 HTTP/1.1
Host: __secs__host
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://__secs__host/console/app.showComp.cmd?Id=2636&urlModifier=34
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en_US; JSESSIONID=__secs__auth_token

                        """,
                              "extractions": [r'NAME="oid" VALUE="(?P<__secs__rule_id>.*?:.*?)".*?__secs__trip_rule'],
                              },
                    {'request': """POST /console/app.showEditor.cmd?editorName=element.editor.check&wndName=PropEditor:element.editor.check HTTP/1.1
Host: __secs__host
Connection: close
Content-Length: 307
Cache-Control: max-age=0
Origin: https://10.0.101.143
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://__secs__host/plugins/console/vessel.jsp?idx=0
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en; JSESSIONID=__secs__auth_token

rows=3&immutable=true&immutable_sng_with_nodes=false&deletable=true&currentView=tableView&searchCacheKey=nodeManager.nodeNavigationPage.navComp.table.content.content&isMembershipAlterable=true&tableType=nodes&oid=__secs__endpoint_id&cmd=&cmdId=&CSRF_TOKEN=__secs__csrf_token"""},
            {'request': """GET /console/app.showComp.cmd?Id=6765&selectedRule=__secs__rule_id&selectedPath=__secs__rule_id HTTP/1.1
Host: __secs__host
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://__secs__host/console/app.showComp.cmd?Id=6766&urlModifier=265%2C266&objType=nodes&nodesHaveEls=true&searchCacheKey=nodeManager.nodeNavigationPage.navComp.table.content.content&dlgCtxId=-9223372036854775806
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en; JSESSIONID=__secs__auth_token"""},

                             {"request": """POST /console/app.applyEditorChanges.cmd HTTP/1.1
Host: __secs__host
Connection: close
Content-Length: 730
Cache-Control: max-age=0
Origin: https://__secs__host
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://10.0.101.143/console/app.showComp.cmd?Id=6759&urlModifier=265%2C266&objType=nodes&nodesHaveEls=true&searchCacheKey=nodeManager.nodeNavigationPage.navComp.table.content.content&searchCacheKey=nodeManager.nodeNavigationPage.navComp.table.content.content&dlgCtxId=-9223372036854775779
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en_US; JSESSIONID=__secs__auth_token

editorId=6757&dlgCtxId=-9223372036854775779&searchCacheKey=nodeManager.nodeNavigationPage.navComp.table.content.content&element.editor.check.sheet.content.checkType=element.editor.check.sheet.content.checkType.selectedRuleGroupable&element.editor.check.sheet.content.baselineType=element.editor.check.sheet.content.baselineType.new&deletable=true&currentView=tableView&rows=3&editorName=element.editor.check&cmd=&CSRF_TOKEN=__secs__csrf_token&immutable_sng_with_nodes=false&oid=__secs__endpoint_id&tableType=nodes&immutable=true&wndName=PropEditor%3Aelement.editor.check&isMembershipAlterable=true&selectedRule=__secs__rule_id&cmdId=6760""",
                              'sleep':10,
                              },
                             {  'urlencode': True,
                                 'request':"""POST /console/app.applyEditorChanges.cmd HTTP/1.1
Host: __secs__host
Connection: close
Content-Length: 473
Cache-Control: max-age=0
Origin: https://10.0.101.143
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://__secs__host/console/app.showComp.cmd?Id=2735&urlModifier=66%2C86&childGroup=-1y2p0ij32e7qz%3A-1y2p0ij2qs9yg&removeObjectsDialog.count=1&searchCacheKey=ruleManager.ruleNavigationPage.navComp.table.content.content&searchCacheKey=ruleManager.ruleNavigationPage.navComp.table.content.content&dlgCtxId=-9223372036854775785
Accept-Language: en-US,en;q=0.8
Cookie: testForCookies=success; localeId=en_US; JSESSIONID=__secs__auth_token

editorId=2733&dlgCtxId=-9223372036854775785&searchCacheKey=ruleManager.ruleNavigationPage.navComp.table.content.content&removeObjectsDialog.sel=ruleManager.editor.delete.sel.removeLater&editorName=ruleManager.editor.delete&cmd=&CSRF_TOKEN=__secs__csrf_token&oid=__secs__rule_id&wndName=PropEditor%3AruleManager.editor.delete&isMembershipAlterable=true&currentView=tableView&rows=18&cmdId=2736""",

                              },
             ]
        }
     ## initialize HTTP integrator class
        super(Module, self).__init__(discovery_conf=self.discovery_conf, authentication_conf=self.authentication_conf,
                                     enumeration_conf=self.enumeration_conf, smash_conf=self.smash_conf,
                                     info=self.info)


