import re

IP = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

def parse_log(log):
    log_header = '.*?([A-Za-z0-9_-]+) %(?:FWSM|ASA)-[0-9]-[0-9]+: Built (inbound|outbound) (TCP|UDP|ICMP) connection (.*)'

    result = re.match(log_header, log)

    if not result:
        return None

    fields = ('context', 'direction', 'ip_proto', '_rest')
    info = dict(zip(fields, result.groups()))
    proto_map = {
        'ICMP': _parse_icmp,
        'TCP': _parse_tcp_udp,
        'UDP': _parse_tcp_udp
    }

    if info['ip_proto'] in proto_map:
        parse_proto = proto_map[info['ip_proto']]

        rest = info['_rest']
        del info['_rest']

        return parse_proto(rest, info)
    else:
        print('Unknown protocol: ', info['ip_proto'])
        return None

def _parse_icmp(log, info):
    icmp_regex = 'for faddr (#{ip})\/([0-9]+) gaddr #{ip}\/[0-9]+ laddr (#{ip})\/([0-9]+)'.replace('#{ip}', IP)
    result = re.match(icmp_regex, log)

    if not result:
        return None

    info.update({
        'ip_src': result.group(1),
        'ip_dst': result.group(3)
    })

    return info

def _parse_tcp_udp(log, info):
    tcp_udp_regex = '([0-9]+) for [a-zA-Z0-9\._-]+:(#{ip})\/([0-9]+) \([^\)]+\) to [a-zA-Z0-9\._-]+:(#{ip})\/([0-9]+)'.replace('#{ip}', IP)
    result = re.match(tcp_udp_regex, log)

    if result is None:
        return None

    fields = 'conn_id', 'ip_src', 'src_port', 'ip_dst', 'dst_port'
    info.update(zip(fields, result.groups()))


    return info

if __name__ == '__main__':
    import sys
    for line in open(sys.argv[1]):
        parsed = parse_log(line)
        if parsed is not None:
            print(parsed)
