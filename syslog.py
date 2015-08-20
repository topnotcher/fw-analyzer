import logging
from time import mktime, strptime, strftime

class SyslogListener(object):
    def syslog_received(self, time, src, msg):
        raise NotImplementedError

class SyslogServer(object):
    def __init__(self, bind_addr='0.0.0.0', bind_port=514):
        self._bind = (bind_addr, bind_port)
        self._loop = None
        self._transport = None
        self._listeners = []
        self.log = logging.getLogger(self.__class__.__name__)

    def register_listener(self, listener):
        self._listeners.append(listener)

    def start(self, loop):
        self._loop = loop

        listen = self._loop.create_datagram_endpoint(lambda: self, local_addr=self._bind)
        self._loop.run_until_complete(listen)

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        for log in data.split(b'\n'):
            try:
                if log:
                    self._handle_log(log)
            except:
                self.log.error('Unhandled exception handling log')

    def _handle_log(self, log):
        try:
            pri, time, src, msg = self._parse_log(log)
        except ValueError as err:
            self.log.error('Failed to parse msg: %r', msg)
            self.log.error('=> %s', str(err))
            return
        except Exception as err:
            self.log.exception(err)

        self._dispatch_event(time, src, msg)

    def _dispatch_event(self, time, src, msg):
        for listener in self._listeners:
            try:
                listener.syslog_received(time, src, msg)
            except Exception as err:
                self.log.error('Caught exception while dispatching event to %s', listener.__class__.__name__)
                self.log.exception(err)

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
        return s_time, log[16:]

    @staticmethod
    def _parse_src(log):
        rpos = log.index(b' ')
        return log[:rpos], log[rpos+1:]

    def __del__(self):
        if self._transport:
            self._transport.close()

if __name__ == '__main__':
    import sys, asyncio, logging
    from .cisco.client import CiscoSSHClient
    from .cisco.manager import CiscoFwManager

    logging.basicConfig(level=logging.DEBUG)

    loop = asyncio.get_event_loop()

    server = SyslogServer(bind_port=50514)
    server.start(loop)

    conn = CiscoSSHClient(sys.argv[1], sys.argv[2], sys.argv[3], loop)
    manager = CiscoFwManager(conn, loop, None)

    server.register_listener(manager)

    loop.run_forever()
