from ssmodules import cbr
from seclib import models



print "test authentication"

cbr_mod = cbr.Module()

credential = {
    'username': '',
    'password': ''
}

print cbr_mod.get_discovery_dict

test_host = models.Controller(host='', port='443', ssl=True)


hosts = [test_host,]
cbr_mod.authenticate(host=test_host,credential=credential)
print hosts[0].auth_token



cbr_mod.enumerate(test_host)

print test_host.endpoints

print 'smashtesting'


cbr_mod.smash(host=test_host,
              command='',
  endpoint_list=None)
