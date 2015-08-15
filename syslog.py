from time import mktime, strptime, strftime

import pub

class SyslogServer(object):
    def __init__(self, bind_addr='0.0.0.0', bind_port=514):
        self._bind = (bind_addr, bind_port)
        self._loop = None
        self._transport = None

    def start(self, loop):
        self._loop = loop

        listen = self._loop.create_datagram_endpoint(lambda: self, local_addr=self._bind)
        self._loop.run_until_complete(listen)

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        try:
            pri, time, src, msg = self._parse_log(data)
            self._dispatch_event(time, src, msg)
        except ValueError as err:
            print(err)
            return

    def _dispatch_event(self, time, src, msg):
        pub.publish('syslog', time=time, src=src, msg=msg)

    def _parse_log(self, log):
        pri, log = self._parse_pri(log)
        time, log = self._parse_timestamp(log)
        src, log = self._parse_src(log)

        return pri, time, src, log

    @staticmethod
    def _parse_pri(log):
        # The PRI part MUST have 3, 4, or 5 chars and will be bounded by angle
        # brackets.

        if log[0:1] != b'<':
            raise ValueError('Log does not start with <')
        else:
            lpos = 1

        rpos = log.find(b'>', 2, 5)
        if rpos == -1:
            raise ValueError('pri does not end with >')

        pri = log[lpos:rpos].decode('ascii')
        if not pri.isdigit():
            raise ValueError('PRI not digits')

        return int(pri), log[rpos+1:]

    @staticmethod
    def _parse_timestamp(log):
        year = strftime('%Y')
        time_str = log[:15].decode('ascii').replace('  ', ' 0') + ' ' + year
        s_time = strptime(time_str, '%b %d %H:%M:%S %Y')
        return mktime(s_time), log[16:]

    @staticmethod
    def _parse_src(log):
        rpos = log.index(b' ')
        return log[:rpos], log[rpos+1:]

    def __del__(self):
        if self._transport:
            self._transport.close()

if __name__ == '__main__':
    import asyncio
    server = SyslogServer(bind_port=50514)

    def receiver(src, time, msg):
        print('Syslog Received: [%f](%s): %s' % (time, src, msg))

    pub.subscribe('syslog', receiver)

    loop = asyncio.get_event_loop()
    server.start(loop)
    loop.run_forever()
