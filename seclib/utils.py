
## https://gist.github.com/bgusach/a967e0587d6e01e889fd1d776c5f3729
import re
import base64
from functools import reduce  # forward compatibility for Python 3
import operator
import urllib

def dict_listkey(dataDict, mapList):
    return reduce(operator.getitem, mapList, dataDict)



def multireplace(request, replacements):
    """
    Given a string and a replacement map, it returns the replaced string.
    :param str string: string to execute replacements on
    :param dict replacements: replacement dictionary {value to find: value to replace}
    :rtype: str
    """
    # Place longer ones first to keep shorter substrings from matching where the longer ones should take place
    # For instance given the replacements {'ab': 'AB', 'abc': 'ABC'} against the string 'hey abc', it should produce
    # 'hey ABC' and not 'hey ABc'

    string = request['request']
    if 'urlencode' in request:
        urlencode = request['urlencode']

        for key, replacement in replacements.iteritems():
            if isinstance(replacement,basestring):
                if urlencode ==True or key in urlencode:
                    replacements[key] = urllib.quote_plus(replacement)


    substrs = sorted(replacements, key=len, reverse=True)

    # Create a big OR regex that matches any of the substrings to replace
    regexp = re.compile('|'.join(map(re.escape, substrs)))

    # For each match, look up the new string in the replacements
    return regexp.sub(lambda match: str(replacements[match.group(0)]), string)

## https://stackoverflow.com/questions/38987/how-to-merge-two-python-dictionaries-in-a-single-expression
def merge_two_dicts(x, y):
    """Given two dicts, merge them into a new dict as a shallow copy."""
    z = x.copy()
    z.update(y)
    return z

def make_basic_auth_header(username, password):
    auth = base64.b64encode(username +":" + password)
    return "Authorization: Basic " + auth


## https://stackoverflow.com/questions/11157704/python-intersection-between-a-list-and-keys-of-a-dictionary
def intersect_dict_with_list(dict, list):
    keys = set(list).intersection(dict)
    result = {k:dict[k] for k in keys}
    return result


def extract_groupdict(text,extraction):
    p = re.compile(extraction)
    m = p.search(text)
    if m:
        groupdict = m.groupdict()
        return groupdict
def extract_multi_groupdict(text,extraction):
    p = re.compile(extraction)
    groupdicts = [m.groupdict() for m in p.finditer(text)]
    return groupdicts

def check_required_vars(vars, required_vars):
    passed = 0
    for var in required_vars:
        if var in vars:
            passed +=1
    return (passed == len(required_vars))

