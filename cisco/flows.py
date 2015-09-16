import re

import logging

from .acl import parse as acl_parse

__ALL__ = ['FlowAnalyzer']

class FlowAnalyzer(object):
    def __init__(self, manager, context):
        self._context = context
        self._manager = manager

        self._acls = {}

        self._manager.subscribe(self._manager.CONFIG_EVENT, 'updated', self._get_acls)
        self._manager.subscribe(self._manager.LOG_EVENT, '6-106100', self._acl_entry_hit)


        self.log = logging.getLogger(self.__class__.__name__)

        # This gets the ACLs on startup
        # NOTE: If the config is different than the saved config, we'll pull
        # the ACL's twice: once now and once when the 'config updated' event is
        # received.
        self._get_acls()

    def _get_acls(self):
        self._context.exec_cmd_callback('show access-list', self._update_acl)

    def _update_acl(self, show_acl):
        for acl in acl_parse(show_acl):
            self._acls[acl.name] = {}

            for ace in acl:
                # only process ACEs with logging
                #if not ace.entry.get('log', None):
                    #continue

                # TODO: index ace by hash
                self._acls[acl.name][ace.entry['hash']] = ace
                self.log.debug('%s line %d hash 0x%08x', acl.name, ace.entry['line'], ace.entry['hash'])

    def _acl_entry_hit(self, time, msg):
        PATTERN = r'^access-list ([^ ]+) (permitted|denied) (udp|tcp|icmp) '\
                  r'([^/]+)/([0-9\.]+)\(([0-9]+)\) -> ([^/]+)/([0-9\.]+)\(([0-9]+)\) '\
                  r'hit-cnt ([0-9]+) (first hit|[0-9]+-second interval) \[(0x[a-f0-9]+), (0x[a-f0-9]+)'

        result = re.match(PATTERN, msg)
        if not result:
            return

        fields = ('acl_name', 'action', 'ip_proto', 'src_int', 'src_ip',
                  'src_port', 'dst_int', 'dst_ip', 'dst_port', 'hit_cnt',
                  'interval_spec', 'ace_hash', 'rule_hash')

        hit = dict(zip(fields, result.groups()))

        # TODO
        hit['ace_hash'] = int(hit['ace_hash'], 16)
        hit['rule_hash'] = int(hit['rule_hash'], 16)
        if hit['rule_hash'] == 0:
            hit['rule_hash'] = hit['ace_hash']

        if hit['acl_name'] not in self._acls:
            self.log.debug('Hit for "%s" not in ACLs', hit['acl_name'])

        elif hit['ace_hash'] not in self._acls[hit['acl_name']]:
            self.log.debug('hash 0x%08x missing from ACL', hit['ace_hash'])

        else:
            acl = self._acls[hit['acl_name']]
            ace_hash = hit['ace_hash']
            ace = acl[ace_hash]

            self.log.debug('Hit %s', str(ace))

            # TODO
            #self.log.debug('Rule: %s', str(ace[rule_hash]))

