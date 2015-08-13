import re

ip = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

crazy_regex = '.*?([A-Za-z0-9_-]+) %(?:FWSM|ASA)-[0-9]-[0-9]+: Built (inbound|outbound) (TCP|UDP|ICMP) connection (?:for faddr (#{ip})\/([0-9]+) gaddr #{ip}\/[0-9]+ laddr (#{ip})\/([0-9]+)|[0-9]+ for [a-zA-Z0-9\._-]+:(#{ip})\/([0-9]+) \([^\)]+\) to [a-zA-Z0-9\._-]+:(#{ip})\/([0-9]+))'.replace('#{ip}', ip)

for line in open('data/topsnt.log'):
    #print(crazy_regex)
    r = re.match(crazy_regex, line)
    if r is None:
        continue
    print(r.groups())


