import re

__ALL__ = ['FlowAnalyzer']

class FlowAnalyzer(object):
    def __init__(self, manager, context):
        self._context = context
        self._manager = manager

        self._manager.subscribe(self._manager.CONFIG_EVENT, 'updated', self._config_updated)
        self._manager.subscribe(self._manager.LOG_EVENT, '6-106100', self._acl_entry_hit)

    def _config_updated(self):
        self._context.exec_cmd_callback('show access-list', self._update_acl)

    def _update_acl(self, acl):
        pass

    def _acl_entry_hit(self, time, msg):
        PATTERN = r'^access-list ([^ ]+) (permitted|denied) (udp|tcp|icmp) '\
                  r'([^/]+)/([0-9\.]+)\(([0-9]+)\) -> ([^/]+)/([0-9\.]+)\(([0-9]+)\) '\
                  r'hit-cnt ([0-9]+) (first hit|[0-9]+-second interval) \[(0x[a-f0-9]+), '

        result = re.match(PATTERN, msg)
        if not result:
            return

        fields = ('acl_name', 'action', 'ip_proto', 'src_int', 'src_ip',
                  'src_port', 'dst_int', 'dst_ip', 'dst_port', 'hit_cnt',
                  'interval_spec', 'hash')

        hit = dict(zip(fields, result.groups()))
