import inspect
import re
import logging

__ALL__ = ['parse']

class ACL(object):
    def __init__(self, name):
        self.name = name
        self.rules = []

    def add_ace(self, ace):
        self.rules.append(ace)

    def __str__(self):
        st = 'Access list: %s\n' % self.name

        for rule in self.rules:
            st += str(rule) + '\n'

        return st

    def __iter__(self):
        for rule in self.rules:
            yield rule

class ACE(object):
    def __init__(self, entry, remarks=None):
        self.entry = entry
        self.rules = []
        self.remarks = remarks

    def add_rule(self, rule):
        self.rules.append(rule)

    def __str__(self):
        st = '\n'.join(self.remarks) + '\n' + '-' * 100 + '\n'
        st += self._str_rule(1, self.entry)
        st +=  '-' * 100 + '\n'
        for rule in self.rules:
            st += self._str_rule(2, rule)

        return st

    @staticmethod
    def _str_rule(level, rule):
        st = ' ' * (4*level) + rule['_raw'] + '\n'
        for field in rule:
            if field not in ('_raw', 'acl_name'):
                st +=  ' '*(4*(level+1)) + '%s: %s\n' % (field, str(rule[field]))

        return st

    def __iter__(self):
        for rule in self.rules:
            yield rule

def get_indent(line):
    i = 0
    for ch in line:
        if ch != ' ':
            break
        else:
            i += 1
    return i

def parse_hdr(line):
    pcs = line.split('; ')

    word, name = pcs[0].split(' ')
    assert word == 'access-list'

    elements, word = pcs[1].split(' ')
    assert word == 'elements'

    return name, int(elements)

def is_ip_addr(ip):
    octets = [int(octet) for octet in ip.split('.', 3) if octet.isdigit()]
    return len(octets) == 4 and min(octets) >= 0 and max(octets) <= 255

class ACELineParser(object):
    def __init__(self, line):
        self.line = line
        self.toks = []
        self.data = {}
        # self.data.keys(), but ordered
        self.populated = []

    def populate(self, key, val):
        self.data[key] = val
        self.populated.append(key)

    def parse(self):
        line = self.line.strip()
        self.data['_raw'] = line
        self.toks = line.split()

        while len(self.toks) > 0:
            self.consume_toks()

        return self.data

    def consume_toks(self):
        methods = inspect.getmembers(self, self.isinstancemethod)
        consumers = (meth[1] for meth in methods if meth[0].startswith('_consume'))

        start_len = len(self.toks)
        for meth in consumers:
            if len(self.toks):
                meth()
            else:
                return

        if len(self.toks) == start_len:
            raise ValueError('Unable to consume all toks: (%s)\n%s' % (', '.join(self.toks), str(self.data)))

    def isinstancemethod(self, meth):
        if not inspect.ismethod(meth):
            return False
        elif type(meth.__self__) != type(self):
            return False

        return True

    def require_next_tok(*args):
        """
        Require that the next token be in *args
        """
        def decorate(meth):
            def validate(ins):
                if ins.toks[0] in args:
                    meth(ins)
            return validate

        return decorate


    def consume_next_tok(*args):
        """
        same as require_next tok, but consume it.
        """
        def decorate(meth):
            def validate(ins):
                if ins.toks[0] in args:
                    ins.toks.pop(0)
                    meth(ins)
            return validate

        return decorate

    def require_not_populated(*args):
        """
        Require that not all of the arguments have been parsed
        """
        def decorate(meth):
            def validate(ins):
                if set(args) - set(ins.populated):
                    meth(ins)
            return validate

        return decorate

    def require_populated(*args):
        """
        Require that all of the arguments have been parsed
        """
        def decorate(meth):
            def validate(ins):
                if not (set(args) - set(ins.populated)):
                    meth(ins)
            return validate

        return decorate

    def require_prev_field(*args):
        def decorate(meth):
            def validate(ins):
                if ins.populated[-1] in args:
                    meth(ins)
            return validate

        return decorate

    @consume_next_tok('access-list')
    @require_not_populated('acl_name')
    def _consume_acl_name(self):
        self.populate('acl_name', self.toks.pop(0))

    @consume_next_tok('line')
    @require_not_populated('line')
    def _consume_line_number(self):
        self.populate('line', int(self.toks.pop(0)))

    @require_next_tok('standard', 'extended', 'remark')
    @require_not_populated('type')
    def _consume_type(self):
        self.populate('type', self.toks.pop(0))
        if self.data['type'] == 'remark':
            self.populate('remark', ' '.join(self.toks))
            self.toks = []

    @require_next_tok('permit', 'deny')
    @require_not_populated('action')
    def _consume_action(self):
        self.populate('action', self.toks.pop(0))

    @require_not_populated('ip_proto')
    @require_prev_field('action')
    def _consume_ip_proto(self):
        if self.data['type'] == 'standard':
            return

        next_tok = self.toks.pop(0)

        if next_tok in ('object-group', 'object'):
            proto = {next_tok: self.toks.pop(0)}
        else:
            proto = next_tok

        self.populate('ip_proto', proto)

    @require_prev_field('action')
    def _consume_std_dst(self):
        if self.data['type'] == 'standard':
            self.populate('dst', self._try_consume_src_dst(self.toks))

    @require_prev_field('ip_proto')
    def _consume_src_dst(self):
        """
        This is a stupid and ugly way of parsing source/source port/dst/dest port.

        Objects or object groups could look like a source port or a
        destination. It's easy to tell if you have the object definition handy,
        but based on the ACE alone is more difficult: if the thing after the
        source parses correctly as a service or a destination, try parsing
        further to see if there is a valid destination.
        """
        self.populate('src', self._try_consume_src_dst(self.toks))

        test_dst_toks = self.toks[:]
        test_sport_toks = self.toks[:]
        dst = self._try_consume_src_dst(test_dst_toks)
        sport = self._try_consume_sport_dport(test_sport_toks)

        # could be either (object or object-group)
        if sport and dst:
            # if it's an sport, it needs to be followed by a dst
            if self._try_consume_src_dst(test_sport_toks):
                self.populate('src_service', self._try_consume_sport_dport(self.toks))
                self.populate('dst', self._try_consume_src_dst(self.toks))

                if self._try_consume_sport_dport(self.toks[:]):
                    self.populate('dst_service', self._try_consume_sport_dport(self.toks))

            # if it's a dst, it needs to be followed by a dport, or nothing
            else:
                self.populate('dst', self._try_consume_src_dst(self.toks))

                #print(', '.join(self.toks))
                #print(len(self.toks))
                if self._try_consume_sport_dport(test_dst_toks):
                    self.populate('dst_service', self._try_consume_sport_dport(self.toks))

        # next thing could be a src/dst or source port.
        elif sport:
            self.populate('src_service', self._try_consume_sport_dport(self.toks))
            self.populate('dst', self._try_consume_src_dst(self.toks))

            if self._try_consume_sport_dport(self.toks[:]):
                self.populate('dst_service', self._try_consume_sport_dport(self.toks))

        elif dst:
            self.populate('dst', self._try_consume_src_dst(self.toks))

            if self._try_consume_sport_dport(self.toks[:]):
                self.populate('dst_service', self._try_consume_sport_dport(self.toks))

    def _try_consume_src_dst(self, toks):
        if not len(toks):
            return None

        next_tok = toks[0]
        next_next_tok = toks[1] if len(toks) > 1 else None
        target = {}

        if next_tok == 'host':
            toks.pop(0)
            target['host'] = toks.pop(0)

        elif next_tok == 'range' and is_ip_addr(next_next_tok):
            toks.pop(0)
            target['range'] = (toks.pop(0), toks.pop(0))

        elif is_ip_addr(next_tok) and is_ip_addr(next_next_tok):
            target['net'] = (toks.pop(0), toks.pop(0))

        elif next_tok in ('object-group', 'object'):
            toks.pop(0)
            target[next_tok] = toks.pop(0)

        # @TODO
        elif next_tok in ('any', 'any4', 'any6'):
            toks.pop(0)
            target['any'] = True

        return target

    #@require_prev_field('src', 'dst')
    def _try_consume_sport_dport(self, toks):
        if not len(toks):
            return None

        next_tok = toks[0]
        next_next_tok = toks[1] if len(toks) > 1 else None
        target = {}

        if next_tok in ('eq', 'neq', 'gt', 'lt'):
            qual = toks.pop(0)
            target[qual] = toks.pop(0)

        elif next_tok == 'range': # and next_next_tok.isdigit():
            toks.pop(0)
            target['range'] = (toks.pop(0), toks.pop(0))

        # TODO: remove echo reply from the F
        # TODO: remove echo reply from the FWW
        elif self.data['ip_proto'] == 'icmp' and next_tok in ('echo', 'echo-reply', 'time-exceeded', 'unreachable'):
            target['icmp_type'] = toks.pop(0)

        elif next_tok in ('object-group', 'object'):
            toks.pop(0)
            target[next_tok] = toks.pop(0)

        return target

    @consume_next_tok('time-range')
    def _consume_time_range(self):
        self.populate('time-range', self.toks.pop(0))

    @consume_next_tok('log')
    def _consume_log(self):
        next_tok = self.toks[0]

        levels = ('emergencies', 'warnings', 'informational',
                  'disable', 'errors', 'alerts', 'debugging')

        if next_tok in levels or next_tok.isdigit():
            level = self.toks.pop(0)

            if level != 'disabled':
                self.populate('log', level)

        next_tok = self.toks[0]
        if next_tok == 'interval':
            self.toks.pop(0)
            self.toks.pop(0)

    @consume_next_tok('inactive', '(inactive)')
    def _consume_inactive(self):
        self.populate('inactive', True)

    def _consume_hitcnt(self):
        next_tok = self.toks[0]
        if re.match('\(hitcnt=[0-9]+\)', next_tok):
            self.toks.pop(0)

    def _consume_hash(self):
        next_tok = self.toks[0]
        if re.match('0x[a-f0-9]+', next_tok):
            self.populate('hash', int(self.toks.pop(0), 16))

class _Iterator(object):
    def __init__(self, lst):
        self._list = lst
        self._idx = -1

    def __iter__(self):
        return self

    def __next__(self):
        self._idx += 1

        if self._idx >= len(self._list):
            raise StopIteration

        return self.cur()

    def prev(self):
        self._idx -= 1
        return self.cur()

    def cur(self):
        return self._list[self._idx]

class ACLParser(object):
    def __init__(self, name):
        self.remarks = []

        self.acl = ACL(name)
        self.ace = None

    def consume(self, it):
        try:
            line = next(it)

            level = get_indent(line)

            parser = ACELineParser(line)
            data = {}
            data = parser.parse()

            if level == 0:
                if data['type'] == 'remark':
                    self.remarks.append(data['remark'])
                else:
                    if self.ace is not None:
                        self.acl.add_ace(self.ace)

                    self.ace = ACE(data, self.remarks)
                    self.remarks = []

            elif level == 2:
                self.ace.add_rule(data)

        except StopIteration:
            pass

        return self.acl

def parse(data):

    i = iter(data.splitlines())

    acls = []
    acl = None
    ace = None
    remarks = []
    for line in i:
        result = re.match('access-list [^;]+; [0-9]+ elements;', line)
        if result:
            acl_name, _ = parse_hdr(line)

            if acl:
                acls.append(acl)

            acl = ACL(acl_name)

        elif acl and line.startswith('access-list ' + acl.name):
            level = get_indent(line)

            parser = ACELineParser(line)
            data = {}
            data = parser.parse()

            if level == 0:
                if data['type'] == 'remark':
                    remarks.append(data['remark'])
                else:
                    if ace is not None:
                        acl.add_ace(ace)

                    ace = ACE(data, remarks)
                    remarks = []

            elif level == 2:
                ace.add_rule(data)

    if acl:
        acls.append(acl)
        if ace:
            acl.add_ace(ace)

    return acls

if __name__ == '__main__':
    with open('../data/acl2.txt') as fh:
        acls = parse(fh.read())

        print('%d acls' % len(acls))
        for acl in acls:
            print(acl)
