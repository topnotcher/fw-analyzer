"""
Utilities for managing Cisco ASAs in single or multiple context mode.

In multiple context mode, all of the contexts can be managed by a single
class:`CiscoFwManager` instance, which relies on a
class:`_MultiContextExecutor` instance to ensure that context commands are
executed in the appropriate context.
"""

__ALL__ = ['CiscoFwManager']

import asyncio
import re
import logging

from ..syslog import SyslogListener
from .client import CiscoSSHClient

class _CiscoFwContext(object):
    """
    A single Cisco firewall or firewall context: either a single context of a
    device in multiple context mode or a single device in single context mode.
    In either case, meth:`exec_cmd` and meth:`exec_cmd_callback` should run
    commands appropriately.
    """

    def __init__(self, name, conn, is_admin=False, sys_conn=None):
        """
        :param name: The name of the context or hostname of the device.
        :param conn: The SSH connection to the ASA. This is either a
        class:`_SingleContextExecutor` instance or a class:`CiscoSSHClient`
        instance.
        :param is_admin: Whether this is the admin context.
        :param sys_conn: If this is the admin context, a
        class:`_SingleContextExecutor` instance pointing to the system context.
        """
        self._name = name
        self._is_admin = is_admin
        self._ips = []
        self._conn = conn

        if self._is_admin:
            self._sys_conn = sys_conn

        log_name = '%s(%s)' % (self.__class__.__name__, self._name)
        self.log = logging.getLogger(log_name)

        #  NOTE: This does _not_ filter out addresses on down interfaces.
        self.exec_cmd_callback('show run ip address', self._populate_ips)

    def _populate_ips(self, show_ip):
        """
        Populate the list of IP addresses defined on this firewall.
        """
        self._ips = _parse_show_run_ip_addrs(show_ip)
        self.log.info('Found IPs %s', ', '.join(self._ips))

    @asyncio.coroutine
    def exec_cmd(self, cmd):
        """
        When the firewall is in single context mode, this is essentially a
        wrapper around CiscoSSHClient.exec_cmd(). In multiple context mode, it
        behaves the same way, but is a wrapper around
        _SingleContextExecutor.exec_cmd().

        See class:`_MultiContextExecutor` and class:`_SingleContextExecutor`
        """
        return (yield from self._conn.exec_cmd(cmd))

    def exec_cmd_callback(self, cmd, callback):
        """
        When the firewall is in single context mode, this is essentially a
        wrapper around CiscoSSHClient.exec_cmd_callback(). In multiple context
        mode, it behaves the same way, but is a wrapper around
        _SingleContextExecutor.exec_cmd_callback().

        See class:`_MultiContextExecutor` and class:`_SingleContextExecutor`
        """
        return self._conn.exec_cmd_callback(cmd, callback)

    def exec_sys_cmd_callback(self, cmd, callback):
        """
        Like meth:`exec_cmd_callback`, but on the system context. Only valid if
        this is the admin context.
        """
        if self.is_admin and self._sys_conn:
            self._sys_conn.exec_cmd_callback(cmd, callback)

    @asyncio.coroutine
    def exec_sys_cmd(self, cmd):
        """
        Like meth:`exec_cmd`, but on the system context. Only valid if this is
        the admin context.
        """
        if self.is_admin and self._sys_conn:
            return (yield from self._sys_conn.exec_cmd(cmd))
        else:
            return None

    def has_ip(self, ipaddr):
        """
        Determine if this context has the given ip address.
        """
        return ipaddr in self._ips

    @property
    def name(self):
        """ Get the name of this context. """
        return self._name

    @property
    def is_admin(self):
        """ Determine if this is the admin context. """
        return self._is_admin

class _MultiContextExecutor(object):
    """
    A proxy to class:`CiscoSSHClient` that allows executing commands on a given
    context when the ASA is in multiple context mode.

    For example: `config = foo.exec_cmd('admin', 'show run')` should _always_
    return the running configuration of the `admin` context.

    When this proxy is used, it is assumed that all commands executed on the
    underlying CiscoSSHClient object are run through this proxy.

    When meth:`exec_cmd` or meth:`exec_cmd_callback` is called  and the
    requested context does not match the current context, a changeto context
    command is sent before sending the actual command. It is thus crucial that
    commands are executed in order. Synchronization is guaranteed by
    CiscoSSHClient.
    """
    def __init__(self, conn):
        self._conn = conn
        self._context = None

    @asyncio.coroutine
    def exec_cmd(self, context, cmd):
        """
        Execute a given command on a given context. See
        CiscoSSHClient.exec_cmd().

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

class _SingleContextExecutor(object):
    """
    A wrapper around class:`_MultiContextExecutor` that provides the same
    interface as class:`CiscoSSHClient`. Users of this class do not care
    whether they are using a class:`CiscoSSHClient` or
    class:`_SingleContextExecutor` instance.

    When multiple instances of class:`_SingleContextExecutor` share the same
    `_MultiContextExecutor` instance, class:`_MultiContextExecutor` guarantees
    that meth:`exec_cmd` or meth:`exec_cmd_callback` calls on the
    `_SingleContextExecutor` instance are run on the correct context.
    """
    def __init__(self, context, conn):
        """
        :param string context: The name of the context.
        :param _MultiContextExecutor conn: A _MultiContextExecutor instance
        shared by multiple _SingleContextExecutor instances.
        """
        self._conn = conn
        self._context = context

    @asyncio.coroutine
    def exec_cmd(self, cmd):
        """
        Execute a given command on this context. See CiscoSSHClient.exec_cmd().

        :param string cmd: The command to execute.

        :return: The output of the command.
        """
        return (yield from self._conn.exec_cmd(self._context, cmd))

    def exec_cmd_callback(self, cmd, callback):
        """
        Execute a given command on this context, running a callback on
        completion. See CiscoSSHClient.exec_cmd_callback().

        :param string cmd: The command to execute.
        :param callback: A callback to run on the command's completion. The
        callback takes one or two parameters: (output) or (cmd, output).
        """
        return self._conn.exec_cmd_callback(self._context, cmd, callback)

class CiscoFwManager(SyslogListener):
    """
    Main class for FW management: determines firewall mode, enumerates
    contexts, etc.

    conn = CiscoSSHClient(host, user, pass)
    fw = CiscoFwManager(conn, asyncio.get_event_loop())
    for context in (yield from fw.contexts):
        print(context.exec_cmd('show run'))
    """
    def __init__(self, conn, loop, config):
        self._loop = loop
        self._initialized = asyncio.Event(loop=self._loop)

        self._contexts = []
        self._is_multi_context = False
        self._admin_context = None

        self.log = logging.getLogger(self.__class__.__name__)
        self._client = conn
        self._loop.create_task(self._initialize())

    @asyncio.coroutine
    def _initialize(self):
        """
        Initialize the class:`CiscoFwManager` instance:

        1. Determine if the firewall is in multiple or single context mode.
            - Or if it is in multiple context mode, but we're connecting to a
              single context, treat it like single context mode.
        2. Instantiate a class:`_CiscoFwContext` object for each context.
            - In multiple context mode, each context gets a
              class:`_SingleContextExecutor` instance to allow executing
              commands on the proper context.
            - Each class:`_CiscoFwContext` instance gathers a list of its IP
              addresses so we can filter syslogs to the correct context.

        TODO: creation and deletion of contexts is not yet supported
        """
        is_multi = yield from _is_multi_mode(self._client)

        # If it reports that it is in multiple context mode, we want to know
        # whether we're in the admin context. If we are not in the admin
        # context, we can just treat it like single context mode.
        if is_multi:
            self.log.info('Cisco ASA in multiple context mode.')

            contexts = yield from _get_contexts(self._client)
            if contexts and contexts[0][1]:
                self._is_multi_context = True
            else:
                self._is_multi_context = False
                self.log.info('Falling back to single context!')
        else:
            self.log.info('Cisco ASA in single context mode.')
            self._is_multi_context = False

        if not self._is_multi_context:
            hostname = yield from _get_hostname(self._client)
            contexts = [(hostname, False)]

            # In single mode, just pass through the class:`CiscoSSHClient` instance.
            fw_conn_factory = lambda context: self._client
        else:
            yield from self._client.exec_cmd('changeto context system')
            contexts = yield from _get_contexts(self._client)

            # In multiple context mode, pass each class:`_CiscoFwContext`
            # instance a class:`_SingleContextExecutor` instance that makes it
            # think it is running in single context mode.
            multi_exec = _MultiContextExecutor(self._client)
            fw_conn_factory = lambda context: _SingleContextExecutor(context, multi_exec)

        for name, is_admin in contexts:
            # A bit of a hack: Since any syslogs from the system actually come
            # from the admin context, the admin context becomes responsible for
            # the system context.
            if is_admin:
                context = _CiscoFwContext(name, fw_conn_factory(name), True, fw_conn_factory('system'))
            else:
                context = _CiscoFwContext(name, fw_conn_factory(name), False)

            self.log.info('Context: %s; is_admin=%s', context.name, str(context.is_admin))

            self._contexts.append(context)

        self._initialized.set()

    @property
    @asyncio.coroutine
    def contexts(self):
        """ 
        Return a list of class:`_CiscoFwContext` instances.
        """
        yield from self._initialized.wait()
        return self._contexts

    def syslog_received(self, time, src, msg):
        """
        Handle syslog received events from the SyslogServer.
        """
        if self._check_log_src(src) and self._initialized.is_set():
            parsed = self._parse_log(msg.decode('ascii'))
            if parsed:
                self._handle_log_event(time, src.decode('ascii'), parsed[0], parsed[1])

    def _handle_log_event(self, time, src, evt, msg):
        """
        Handle a syslog event?
        """
        pass

    def _check_log_src(self, src):
        """
        Check if a syslog source address belongs to a context managed by this instance.
        """
        for context in self._contexts:
            if src in self._contexts[context]:
                return True

        return False

    @staticmethod
    def _parse_log(log):
        """
        Parse a Cisco log message into the event ID and the message.

        Assumtion: first part of the log is context/hostname.

        :return: None if the log is not pareable; else (evt, msg)
        """
        result = re.match('^.*(?:ASA|FWSM)-([0-9]-[0-9]+): (.*)$', log)
        if result:
            return result.group(2), result.group(3)
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
def _get_hostname(conn):
    """
    Return the hostname of a device.

    :param conn: An object that behaves like class:`CiscoSSHClient`.
    """
    return (yield from conn.exec_cmd('show hostname'))

@asyncio.coroutine
def _is_multi_mode(conn):
    """
    Determine whether the device is in multiple context mode.

    :param conn: An object that behaves like class:`CiscoSSHClient`.

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

    :param conn: An object that behaves like class:`CiscoSSHClient`.

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
def _test_save_all_configs(manager, loop):
    """
    Test running show run and saving configuration on all contexts.
    """
    from concurrent.futures import ThreadPoolExecutor

    executor = ThreadPoolExecutor(1)

    for context in (yield from manager.contexts):
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
    manager = CiscoFwManager(conn, loop, None)

    loop.create_task(_test_save_all_configs(manager, loop))
    loop.run_forever()

if __name__ == '__main__':
    main()
