from ssmodules import tripwire
from seclib import models



print "test authentication"

trip_mod = tripwire.Module()

credential = {
    'username': '',
    'password': '
}

print trip_mod.get_discovery_dict


test_host = models.Controller(host='',port='443',ssl=True)


hosts = [test_host,]
trip_mod.authenticate(host=test_host,credential=credential)
print hosts[0].auth_token



trip_mod.enumerate(test_host)

print test_host.endpoints

#print 'smashtesting'

#print '\nfiltered to sclaunchpad'
trip_mod.smash(host=test_host,
              command="""""",
              endpoint_list=[''])
