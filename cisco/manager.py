"""
Utilities for managing Cisco ASAs in single or multiple context mode.

In multiple context mode, all of the contexts can be managed by a single
:class:`CiscoFwManager` instance, which relies on a
:class:`MultiContextExecutor` instance to ensure that context commands are
executed in the appropriate context.
"""

__ALL__ = [
    'CiscoFwManager',
    'CiscoFwContext',
    'MultiContextExecutor',
    'enumerate_contexts',
]

import asyncio
import re
import time
import os
import logging

from ..syslog import SyslogListener
from .client import CiscoSSHClient

class CiscoFwContext(object):
    """
    A single Cisco firewall or firewall context: either a single context of a
    device in multiple context mode or a single device in single context mode.
    In either case, :meth:`exec_cmd` and :meth:`exec_cmd_callback` should run
    commands appropriately.
    """

    def __init__(self, name, conn, is_admin=False, sys_conn=None):
        """
        :param name: The name of the context or hostname of the device.
        :param conn: The SSH connection to the ASA. This is either a
        :class:`_SingleContextExecutor` instance or a :class:`CiscoSSHClient`
        instance.
        :param is_admin: Whether this is the admin context.
        :param sys_conn: If this is the admin context, a
        :class:`_SingleContextExecutor` instance pointing to the system context.
        """
        self._name = name
        self._is_admin = is_admin
        self._conn = conn

        if self._is_admin:
            self._sys_conn = sys_conn

    @asyncio.coroutine
    def exec_cmd(self, cmd):
        """
        When the firewall is in single context mode, this is essentially a
        wrapper around CiscoSSHClient.exec_cmd(). In multiple context mode, it
        behaves the same way, but is a wrapper around
        _SingleContextExecutor.exec_cmd().

        ..seealso::
            :class:`MultiContextExecutor` and :class:`_SingleContextExecutor`.
        """
        return (yield from self._conn.exec_cmd(cmd))

    def exec_cmd_callback(self, cmd, callback):
        """
        When the firewall is in single context mode, this is essentially a
        wrapper around CiscoSSHClient.exec_cmd_callback(). In multiple context
        mode, it behaves the same way, but is a wrapper around
        _SingleContextExecutor.exec_cmd_callback().

        ..seealso::
            :class:`MultiContextExecutor` and :class:`_SingleContextExecutor`.
        """
        return self._conn.exec_cmd_callback(cmd, callback)

    @property
    def sys_conn(self):
        if self._is_admin and self._sys_conn:
            return self._sys_conn
        else:
            return None

    @property
    def name(self):
        """ Get the name of this context. """
        return self._name

    @property
    def is_admin(self):
        """ Determine if this is the admin context. """
        return self._is_admin

class MultiContextExecutor(object):
    """
    A proxy to :class:`CiscoSSHClient` that allows executing commands on a given
    context when the ASA is in multiple context mode.

    Example usage is as follows::

        conn = CiscoSSHClient(host, user, pass)
        multi_exec = MultiContextExecutor(conn)

        admin = multi_exec.get_context('admin')
        dmz = multi_exec.get_context('dmz')

        dmz_running_config = yield from dmz.exec_cmd('show run')
        admin_running_config = yield from admin.exec_cmd('show run')


    When MultiContextExecutor is used, it is assumed that all commands executed
    on the underlying :class:`CiscoSSHClient` object are run through the
    MultiContextExecutor instance. In particular, if changeto commands are run
    outside of MultiContextExecutor, bad things happen.

    When :meth:`exec_cmd` or :meth:`exec_cmd_callback` is called  and the
    requested context does not match the context sent in the last changeto
    command, a changeto context command is sent before sending the
    actual command. It is thus crucial that commands are executed in order.
    Synchronization is guaranteed by CiscoSSHClient.
    """
    def __init__(self, conn):
        self._conn = conn
        self._context = None

    @asyncio.coroutine
    def exec_cmd(self, context, cmd):
        """
        Execute a given command on a given context.

        ..seealso:: :meth:`CiscoSSHClient.exec_cmd`.

        :param string context: The context to execute the command on.
        :param string cmd: The command to execute.

        :return: The output of the command.
        """
        if context != self._context:
            yield from self._conn.exec_cmd('changeto context %s' % context)
            self._context = context

        return (yield from self._conn.exec_cmd(cmd))

    def exec_cmd_callback(self, context, cmd, callback):
        """
        Execute a given command on a given context, running a callback on
        completion. See CiscoSSHClient.exec_cmd_callback().

        :param string context: The context to execute the command on.
        :param string cmd: The command to execute.
        :param callback: A callback to run on the command's completion. The
        callback takes one or two parameters: (output) or (cmd, output).
        """
        if context != self._context:
            self._conn.exec_cmd_callback('changeto context %s' % context, None)
            self._context = context

        return self._conn.exec_cmd_callback(cmd, callback)

    def get_context(self, name):
        return _SingleContextExecutor(name, self)

class _SingleContextExecutor(object):
    """
    A wrapper around :class:`MultiContextExecutor` that provides the same
    interface as :class:`CiscoSSHClient`. Users of this class do not care
    whether they are using a :class:`CiscoSSHClient` or
    :class:`_SingleContextExecutor` instance.

    When multiple instances of :class:`_SingleContextExecutor` share the same
    `MultiContextExecutor` instance, :class:`MultiContextExecutor` guarantees
    that :meth:`exec_cmd` or :meth:`exec_cmd_callback` calls on the
    `_SingleContextExecutor` instance are run on the correct context.
    """
    def __init__(self, context, conn):
        """
        :param string context: The name of the context.
        :param MultiContextExecutor conn: A MultiContextExecutor instance
        shared by multiple _SingleContextExecutor instances.
        """
        self._conn = conn
        self._context = context

    @asyncio.coroutine
    def exec_cmd(self, cmd):
        """
        Execute a given command on this context.

        ..seealso:: :meth:`CiscoSSHClient.exec_cmd`.

        :param string cmd: The command to execute.

        :return: The output of the command.
        """
        return (yield from self._conn.exec_cmd(self._context, cmd))

    def exec_cmd_callback(self, cmd, callback):
        """
        Execute a given command on this context, running a callback on
        completion.

        ..seealso:: :meth:`CiscoSSHClient.exec_cmd_callback`

        :param string cmd: The command to execute.
        :param callback: A callback to run on the command's completion. The
        callback takes one or two parameters: (output) or (cmd, output).
        """
        return self._conn.exec_cmd_callback(self._context, cmd, callback)

class _ManagedConfig(object):
    def __init__(self, config_manager, context, store):
        # timestamp the config was last retrieved
        self._config_timestamp = 0
        self._context = context
        self._config_manager = config_manager

        # Some backing store where we save the config
        self._store = store

        # Checksum of the last stored config
        self._checksum = None

        log_name = '%s(%s)' % (self.__class__.__name__, self._context.name)
        self.log = logging.getLogger(log_name)

    def check(self):
        self._context.exec_cmd_callback('show checksum', self._compare_checksum)

    def _compare_checksum(self, show_checksum):
        checksum = _parse_checksum(show_checksum)

        if checksum != self._checksum:
            self.log.debug('Checksum mismatch: updating config!')
            self._get_config()
        else:
            self.log.debug('Checksum matches!')

    def _get_config(self):
        self._context.exec_cmd_callback('show run', self._receive_config)

    def _receive_config(self, config_output):
        checksum_line, config = self._parse_config_checksum(config_output)

        if checksum_line is None:
            return

        checksum = _parse_checksum(checksum_line)
        if checksum is not None:
            self._checksum = checksum
            self._save_config(config)

    def _save_config(self, config):
        self._config_timestamp = time.time()
        self._config_manager.config_updated()

    @staticmethod
    def _parse_config_checksum(config):
        lpos = config.rfind('Cryptochecksum:')
        rpos = -1

        if lpos != -1:
            rpos = config.rfind(os.linesep, lpos)

        if lpos != -1 and rpos != -1:
            cryptochecksum = config[lpos:rpos]
            return cryptochecksum, config[:lpos] + config[rpos+1:]
        else:
            return None, None

class CiscoFwConfigManager(object):
    def __init__(self, manager, context):
        self._context = context
        self._manager = manager

        log_name = '%s(%s)' % (self.__class__.__name__, self._context.name)
        self.log = logging.getLogger(log_name)

        self._configs = [_ManagedConfig(self, context, None)]

        # This is somewhat dirty...
        if self._context.is_admin and self._context.sys_conn:
            self._configs.append(_ManagedConfig(self, self._context.sys_conn, None))

        self.check_config()

    def config_updated(self):
        self.log.debug('Config updated')

    def check_config(self):
        for config in self._configs:
            config.check()

class _CiscoFwContextManager(object):

    def __init__(self, context):
        self._context = context
        self._ips = []
        self._plugins = []

        log_name = '%s(%s)' % (self.__class__.__name__, self._context.name)
        self.log = logging.getLogger(log_name)

        #  NOTE: This does _not_ filter out addresses on down interfaces.
        self._context.exec_cmd_callback('show run ip address', self._populate_ips)

        self._plugins.append(CiscoFwConfigManager(self, self._context))

    def _populate_ips(self, show_ip):
        """
        Populate the list of IP addresses defined on this firewall.
        """
        self._ips = _parse_show_run_ip_addrs(show_ip)
        self.log.info('Found IPs %s', ', '.join(self._ips))

    def has_ip(self, ipaddr):
        """
        Determine if this context has the given ip address.
        """
        return ipaddr in self._ips

    def handle_log_event(self, time, evt, msg):
        self.log.debug('received log event %s: %s', evt, msg)

class CiscoFwManager(SyslogListener):
    """
    Main class for FW management: determines firewall mode, enumerates
    contexts, etc.
    """
    def __init__(self, conn, loop, config):
        self._loop = loop
        self._initialized = asyncio.Event(loop=self._loop)

        self._contexts = []
        self._is_multi_context = False

        self.log = logging.getLogger(self.__class__.__name__)
        self._loop.create_task(self._initialize(conn))

    @asyncio.coroutine
    def _initialize(self, conn):
        contexts = yield from enumerate_contexts(conn)

        num = len(contexts)
        if num > 1 or (num > 0 and contexts[0].is_admin):
            self._is_multi_context = True
        else:
            self._is_multi_context = False

        for context in contexts:
            context_mgr = _CiscoFwContextManager(context)
            self._contexts.append(context_mgr)

        self._initialized.set()

    @property
    @asyncio.coroutine
    def contexts(self):
        """
        Return a list of :class:`CiscoFwContext` instances.
        """
        yield from self._initialized.wait()
        return self._contexts

    def syslog_received(self, time, src, msg):
        """
        Handle syslog received events from the SyslogServer.
        """
        if self._initialized.is_set():
            for context in self._contexts:
                if context.has_ip(src.decode('ascii')):
                    parsed = self._parse_log(msg.decode('ascii'))
                    if parsed:
                        context.handle_log_event(time, parsed[0], parsed[1])

    @staticmethod
    def _parse_log(log):
        """
        Parse a Cisco log message into the event ID and the message.

        Assumtion: first part of the log is context/hostname.

        :return: None if the log is not pareable; else (evt, msg)
        """
        result = re.match('^.*(?:ASA|FWSM)-([0-9]-[0-9]+): (.*)$', log)
        if result:
            return result.group(1), result.group(2)
        else:
            return None

def _parse_show_run_ip_addrs(show_ip):
    """
    Parse the output from `show run ip address` and return a list of IPs.
    """
    ips = []
    for line in show_ip.splitlines():
        result = re.match(r'^ +ip address ([0-9\.]+) ', line)
        if result:
            ips.append(result.group(1))

    return ips

@asyncio.coroutine
def enumerate_contexts(conn):
    """
    A convenience function for managing firewalls in multi context mode. A list
    of :class:`CiscoFwContext` instances is returned with one instance for each
    context. If the firewall is in multiple context mode, the list contains one
    entry.

    ..seealso:: :class:`MultiContextExecutor`.

    For example, to connect to some arbitrary firewall (single or multiple
    context) and retrieve all context configs::

        conn = CiscoSSHClient(host, user, pass, loop)
        for context in (yield from enumerate_contexts(conn)):
            context_config = context.exec_cmd('show run')

    1. Determine if the firewall is in multiple or single context mode.
        - Or if it is in multiple context mode, but we're connecting to a
          single context, treat it like single context mode.
    2. Instantiate a :class:`CiscoFwContext` object for each context.
        - In multiple context mode, each context gets a
          :class:`_SingleContextExecutor` instance to allow executing
          commands on the proper context.
        - Each :class:`CiscoFwContext` instance gathers a list of its IP
          addresses so we can filter syslogs to the correct context.
    """
    log = logging.getLogger('enumerate_contexts')
    is_multi = False

    # If it reports that it is in multiple context mode, we want to know
    # whether we're in the admin context. If we are not in the admin
    # context, we can just treat it like single context mode.
    if (yield from _is_multi_mode(conn)):
        log.info('Cisco ASA in multiple context mode.')

        contexts = yield from _get_contexts(conn)
        if contexts and contexts[0][1]:
            is_multi = True
        else:
            is_multi = False
            log.info('Falling back to single context!')
    else:
        log.info('Cisco ASA in single context mode.')
        is_multi = False

    if not is_multi:
        hostname = yield from _get_hostname(conn)
        contexts = [(hostname, False)]

        # In single mode, just pass through the :class:`CiscoSSHClient` instance.
        fw_conn_factory = lambda context: conn
    else:
        yield from conn.exec_cmd('changeto context system')
        contexts = yield from _get_contexts(conn)

        # In multiple context mode, pass each :class:`CiscoFwContext`
        # instance a :class:`_SingleContextExecutor` instance that makes it
        # think it is running in single context mode.
        multi_exec = MultiContextExecutor(conn)
        fw_conn_factory = lambda context: multi_exec.get_context(context)

    context_objs = []
    for name, is_admin in contexts:
        # A bit of a hack: Since any syslogs from the system actually come
        # from the admin context, the admin context becomes responsible for
        # the system context.
        if is_admin:
            sys_conn = CiscoFwContext('system', fw_conn_factory('system'), False)
            context = CiscoFwContext(name, fw_conn_factory(name), True, sys_conn)
        else:
            context = CiscoFwContext(name, fw_conn_factory(name), False)

        log.info('Context: %s; is_admin=%s', context.name, str(context.is_admin))

        context_objs.append(context)

    return context_objs

def _parse_checksum(checksum):
    """
    Parse the output of show checksum or the checksum in a config.
    """
    # show checksum has spaces >:O
    checksum = checksum.lower().replace(' ', '')
    try:
        key, value = checksum.split(':')
        assert key == 'cryptochecksum'
        return value
    except (ValueError, AssertionError):
        return None

@asyncio.coroutine
def _get_hostname(conn):
    """
    Return the hostname of a device.

    :param conn: An object that behaves like :class:`CiscoSSHClient`.
    """
    return (yield from conn.exec_cmd('show hostname'))

@asyncio.coroutine
def _is_multi_mode(conn):
    """
    Determine whether the device is in multiple context mode.

    :param conn: An object that behaves like :class:`CiscoSSHClient`.

    :return: True if the device is in multiple context mode; False otherwise.
    """
    show_mode = yield from conn.exec_cmd('show mode')

    result = re.match('^Security context mode: (single|multiple)', show_mode)
    if result and result.group(1) == 'multiple':
        return True
    else:
        return False

@asyncio.coroutine
def _get_contexts(conn):
    """
    Retrieve a list of contexts from the device.

    :param conn: An object that behaves like :class:`CiscoSSHClient`.

    :return: A list of (context_name, is_admin_context) tuples.
    """
    show_context = yield from conn.exec_cmd('show context')
    contexts = []

    for line in show_context.splitlines():
        result = re.match(r'^([ \*])([^ ]+) ', line)
        if result:
            is_admin = True if result.group(1) == '*' else False
            contexts.append((result.group(2), is_admin))

    return contexts

@asyncio.coroutine
def _test_save_all_configs(conn, loop):
    """
    Test running show run and saving configuration on all contexts.
    """
    from concurrent.futures import ThreadPoolExecutor
    executor = ThreadPoolExecutor(1)

    contexts = yield from enumerate_contexts(conn)
    for context in contexts:
        # Ten levels of ugly
        def save_context_config(context_name):
            """ so many """

            def _save_context_config(config):
                """ levels """

                # Blocking I/O
                def _save_in_thread():
                    """ of functions """
                    with open('data/config-%s' % context_name, 'w') as config_file:
                        config_file.write(config)
                # run blocking I/O stuff in a thread
                loop.run_in_executor(executor, _save_in_thread)

            return _save_context_config

        context.exec_cmd_callback('show run', save_context_config(context.name))

def main():
    """
    Test some stuff.
    """
    import sys
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.get_event_loop()

    conn = CiscoSSHClient(sys.argv[1], sys.argv[2], sys.argv[3], loop)

    loop.create_task(_test_save_all_configs(conn, loop))
    loop.run_forever()

if __name__ == '__main__':
    main()
