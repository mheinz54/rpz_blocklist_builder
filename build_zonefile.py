import re
import requests
import numpy as np
from django.core.validators import URLValidator


list_of_blocklists_url = 'https://v.firebog.net/hosts/lists.php?type=tick'
stevenblack_hostfile_url = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts'
badsites_topmil_url = 'https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list'
whitelist_remote_url = 'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt'
whitelist_file = "whitelist.txt"
blacklist_file = "blacklist.txt"

def check_url(the_url):
    try:
        URLValidator()(the_url)
        return True
    except:
        return False

def clean_url(the_url):
    if len(the_url) < 1 or the_url[0] == '#':
        return None

    dont_add = ['0.0.0.0', '127.0.0.1', '::1', 'localhost']
    delim = '\t', ' ', '\r', '\n', ':'
    regexPattern = '|'.join(map(re.escape, delim))
    parts = re.split(regexPattern, str(the_url).lower())

    for part in parts:
        if part not in dont_add and len(part) > 3: 
            b_part = part
            if part[-1] == '*': # temp fix: if it ends in a wildcard, change it to .com
                part = part[0:-2] + ".com"
            while len(part) >= 96:
                part = '.'.join(part.split('.')[1:])
            part = part.lstrip('www.')
            #if len(part) > 4:
            if len(part) < 4 or not '.' in part:
                print(b_part + ":::" + part)
            else:
                return part
    return None

blocklist_urls = [x for x in requests.get(list_of_blocklists_url).text.split('\n') if check_url(x)]
blocklist_urls.append(badsites_topmil_url)

zone_set = set()
for url in blocklist_urls:
    zones_lists = requests.get(url).text.split('\n')
    for zone in zones_lists:
        #zone_set.add(str(clean_url(zone)) + "         " + url)
        zone_set.add(clean_url(zone))

# steven black file has a header to remove
zones_lists = requests.get(stevenblack_hostfile_url).text.split('\n')
header = True
for zone in zones_lists:
    if header == True:
        header = False if zone == '# Start StevenBlack' else True
    else:
        zone_set.add(clean_url(zone))

with open(blacklist_file, 'r') as f:
    for line in f:
        zone_set.add(clean_url(line))

# check through whitelist to remove from black
zones_lists = requests.get(whitelist_remote_url).text.split('\n')
white_set = set()
with open('remote_whitelist.txt', 'w') as f:
    for zone in zones_lists:
        u = clean_url(zone)
        white_set.add(u)
        f.write(str(u) + '\n')

with open(whitelist_file, 'r') as f:
    for line in f:
        white_set.add(clean_url(line))
    
print(len(zone_set))
#zone_set = sorted(zone_set - white_set)
zone_set = zone_set - white_set
print(len(zone_set))

with open('rpzzones.db', 'w') as f:
    f.write('; zone file rpzzones.db\n')
    f.write('$TTL    604800\n')
    f.write('@       IN      SOA     sinkhole.mydomain.my. sinkhole.mydomain.my. (\n')
    f.write('                      2         ; Serial\n')
    f.write('                 604800         ; Refresh\n')
    f.write('                  86400         ; Retry\n')
    f.write('                2419200         ; Expire\n')
    f.write('                 604800 )       ; Negative Cache TTL\n')
    f.write('@       IN      NS      sinkhole.mydomain.my.\n')
    f.write('\n')

    for zone in zone_set:
        if len(zone) > 1:
            f.write('%s CNAME .\n' % zone)
            #f.write('*.%s CNAME .\n' % zone) # too aggressive 