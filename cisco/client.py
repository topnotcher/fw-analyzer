"""
Utilities for using asyncio to SSH into a Cisco ASA.
"""

import asyncssh
import asyncio
import os
import re
import inspect
import logging

__ALL__ = [
    'CiscoSSHClient'
    'CiscoFwContext',
    'MultiContextExecutor',
    'enumerate_contexts'
]

PRIV_PROMPT = b'^.+# $'
PASS_PROMPT = b'^Password: $'

class _FutureCommand(asyncio.Future):
    """
    A Future that represents a commands to be run on an ASA at some point in
    the future. If a callback is passed, the callback is called with the output
    of the command.
    """
    def __init__(self, cmd, callback=None):
        """
        :param cmd: Command to run.
        :param callback: None or a callback to call when the command completes.
        The callback takes one argument: the output of the command.
        """
        super(_FutureCommand, self).__init__()
        self._cmd = cmd

        if callback is not None:
            self._cmd_done_callback = callback
            self.add_done_callback(self._future_done)

    def _future_done(self, future):
        """
        Called when the future is done.
        """
        arglen = len(inspect.getargspec(self._cmd_done_callback))
        is_method = inspect.ismethod(self._cmd_done_callback)
        if (arglen == 3 and is_method or
            arglen == 2 and not is_method):
            args = (self.cmd, future.result())
        else:
            args = (future.result(),)

        self._cmd_done_callback(*args)

    @property
    def cmd(self):
        """
        Return the command to be run.
        """
        return self._cmd

class _CiscoSSHClientListener(object):
    def connection_lost(self):
        pass

    def connection_made(self):
        pass

class CiscoSSHClient(asyncssh.SSHClient): # pylint: disable=too-many-instance-attributes
    """
    An asyncio-based SSH connection to a Cisco ASA. The connection is lazy: it
    connects or reconnects when there are commends to run. After connecting, it
    stays connected for _timeout seconds or until the server disconnects it.

    Commands can be executed either as coroutines via meth:`exec_cmd` or
    asynchronously via callbacks: meth:`exec_cmd_callback`.

    It is assumed that the login and enable passwords are the same. Whether or
    not an enable is required is detected by examining the prompt after
    connecting; if it ends with >, "enable" is sent; otherwise auto-enable is
    assumed (available as of ASA 9.1(5)).
    """

    def __init__(self, host, user, passwd, loop):
        """
        :param host: Hostname for SSH connection.
        :param user: Username for the SSH connection.
        :param passwd: Password for the SSH connection and to enable.
        :param loop: asyncio event loop
        """

        self._host = host
        self._login = {'username': user, 'password': passwd}
        self._listeners = []

        self._conn = None
        self._stdin = None
        self._stdout = None
        self._linesep = b'\r\n'
        self._loop = loop

        # Connection idle timeout (client side)
        self._timeout = 180

        self.log = logging.getLogger('%s(%s)' % (self.__class__.__name__, self._host))
        self._queue = asyncio.Queue(loop=self._loop)
        self._running = True
        self._task = self._loop.create_task(self._run())

        self.log.info('Created connection for %s', host)

    @asyncio.coroutine
    def exec_cmd(self, cmd):
        """
        Queue a command for execution and return the result.
        """
        future = self._queue_cmd(cmd)
        result = yield from asyncio.wait_for(future, timeout=None, loop=self._loop)
        return result

    def exec_cmd_callback(self, cmd, callback):
        """
        Queue a command for execution and send the output to a callback on
        completion.

        :param cmd: The command to execute.
        :param callback: The callback to run on completion. It can take one or
        two arguments: (output) or (cmd, output).
        """
        self._queue_cmd(cmd, callback)

    def stop(self):
        """
        Stop the client from running. It is unusable after stopping.
        """
        self.close()
        self._running = False

    def add_listener(self, listener):
        self._listeners.append(listener)

    def connection_made(self, conn): # pylint: disable=unused-argument
        for listener in self._listeners:
            listener.connection_made()

    def connection_lost(self, exc=None):
        """
        Handle connection lost events - called automatically when a connection is lost.
        """
        self._stdin = None
        self._stdout = None
        self._conn = None

        self.log.info('disconnected')

        for listener in self._listeners:
            listener.connection_lost()

    def close(self):
        """
        Close the SSH connection cleanly and discard any pending commands.
        """

        # Cancel any queued futures.
        while not self._queue.empty():
            self._queue.get_nowait().cancel()

        if self._conn:
            try:
                self._send_cmd('exit')
                if self._conn is not None:
                    self._conn.close()
            finally:
                self.connection_lost()

    @asyncio.coroutine
    def _run(self):
        """
        Main client routine: wait for commands to run run them, lazily
        connecting.
        """
        while self._running:
            try:
                timeout = self._timeout if self._conn else None
                fut = yield from asyncio.wait_for(self._queue.get(), loop=self._loop, timeout=timeout)

                yield from self._lazy_connect()
                result = yield from self._exec_cmd(fut.cmd)

                self.log.debug('cmd "%s" collected: %s', fut.cmd, result)
                fut.set_result(result)
            except asyncio.TimeoutError:
                self.close()

        # TODO: needed?
        self._task.cancel()

    @asyncio.coroutine
    def _lazy_connect(self):
        """
        Open a connection to the SSH server if necessary.
        """
        if self._conn is not None:
            return

        self._conn, _ = yield from asyncssh.create_connection(lambda: self, self._host, **self._login)
        self._stdin, self._stdout, _ = yield from self._conn.open_session(encoding=None)

        # If auto-enable is enabled, the prompt will end with #; otherwise it will end with >
        result = yield from self.collect_until_prompt(b'^.+[#>] $')

        # TODO: the result=None case is not handled!
        if result and result[0].endswith('> '):
            yield from self._enable()

        self._send_cmd('terminal pager 0')
        yield from self.collect_until_prompt(PRIV_PROMPT)

    @asyncio.coroutine
    def _enable(self):
        """
        enable: Enter privileged EXEC mode.
        """
        echo_size = self._send_cmd('enable')
        result = yield from self.collect_until_prompt(PASS_PROMPT, ignore_echo=echo_size)

        # TODO: None case not handled
        if result is not None:
            self._send_cmd(self._login['password'])
            yield from self.collect_until_prompt(PRIV_PROMPT)

    @asyncio.coroutine
    def collect_until_prompt(self, prompt, timeout=5.0, ignore_echo=0):
        """
        Collect output until a prompt is found and return the output, excluding the prompt.

        For example, the following SSH session...
        skullcruncher# show run
        <command output>
        skullcruncher#

        could be represented as:
        bytes_sent = self._send_cmd('show run')
        config = yield from self.collect_until_prompt(b'skullcruncher# ', ignore_echo=bytes_sent)

        :param regex prompt: Prompt regex to match.
        :param float timeout: Give up if there has been no data received for
        this many seconds and a prompt has not been found.
        :param integer ignore_echo: Number of characters to discard at the
        beginning of input. When a command is run, this should be set to the
        number of bytes sent to run the command to disregard any echoed output.

        :return: Collected data if a prompt was found; else None
        """
        buf = b''
        select_timeout = 0.1
        timeout_counter = 0.0

        while True:
            try:
                # this is a bittttt nasty but wait() doesn't seem to work right
                # with asyncssh; it doesn't handle canceling properly.
                data = yield from asyncio.wait_for(self._stdout.read(1024), timeout=select_timeout)
                timeout_counter = 0.0
                buf += data
            except asyncio.TimeoutError:
                timeout_counter += select_timeout
                last_line = _get_last_line(buf, self._linesep)
                result = re.match(prompt, last_line)

                if result:
                    drop_len = len(self._linesep) + len(last_line)

                    # Strip echoed chars, drop the last line, and normalize line-endings.
                    output = buf[ignore_echo : -1 * drop_len].replace(self._linesep, os.linesep.encode('utf-8'))

                    return last_line.decode('utf-8'), output.decode('utf-8')
                elif timeout_counter >= timeout:
                    self.log.debug('Collect timed out!')
                    # NOTE: returning None if prompt is not found
                    return None

    def _queue_cmd(self, cmd, callback=None):
        """
        Queue a command for execution.

        :return: The number of bytes sent.
        """
        future = _FutureCommand(cmd, callback)
        self._queue.put_nowait(future)
        return future

    def _send_cmd(self, cmd):
        """
        Send a command to the server.
        """
        self.log.debug('SEND: %s', cmd)
        if not isinstance(cmd, bytes):
            send_cmd = cmd.encode('ascii')
        else:
            send_cmd = cmd

        # NOTE: The device always echoes back CRLF even when I send just LF
        send_cmd += self._linesep
        self._stdin.write(send_cmd)

        return len(send_cmd)

    @asyncio.coroutine
    def _exec_cmd(self, cmd):
        """
        Execute a command returning the result or None if a result was not collected.

        See meth:`collect_until_prompt`
        """
        echo_size = self._send_cmd(cmd)

        result = yield from self.collect_until_prompt(PRIV_PROMPT, ignore_echo=echo_size)

        if not result:
            return None
        else:
            return result[1]

def _get_last_line(buf, sep):
    """
    Get the last line of a buffer.
    """
    pos = buf.rfind(sep)
    if pos == -1:
        return buf
    else:
        return buf[pos + len(sep):]

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

class MultiContextExecutor(_CiscoSSHClientListener):
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
        self._conn.add_listener(self)

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

    def connection_lost(self):
        self._context = None

    def connection_made(self):
        self._context = None

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

@asyncio.coroutine
def enumerate_contexts(conn):
    """
    A convenience function for managing firewalls that may be in multiple
    context mode. A list of :class:`CiscoFwContext` instances is returned with
    one instance for each context. If the firewall is in single context mode,
    the list contains one entry.

    ..seealso::
        :class:`MultiContextExecutor`.
        :class:`_SingleContextExecutor`.
        :class:`CiscoFwContext`.

    To connect to some arbitrary firewall (single or multiple
    context) and retrieve all context configs::

        conn = CiscoSSHClient(host, user, pass, loop)
        for context in (yield from enumerate_contexts(conn)):
            context_config = yield from context.exec_cmd('show run')

    Steps run are as follows:

    1. Determine if the firewall is in multiple or single context mode.
        - Or if it is in multiple context mode, but the connection is to a
          non-admin context, treat it like single context mode.
    2. Instantiate a :class:`CiscoFwContext` object for each context.
        - In multiple context mode, each context gets a
          :class:`_SingleContextExecutor` instance to allow executing commands
          on the proper context.


    :param conn: A CiscoSSHClient instance.
    :return: A list of :class:`CiscoFwContext` instances.
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

### MAIN ###

def _multi_line_cmd_output(cmd, data):
    """ Print multi line output. """
    sep = '-' * 50
    print('%s\n%s\n%s\n%s' % (cmd, sep, data, sep))

def _single_line_cmd_output(cmd, data):
    """ Print single line output. """
    print('%s: %s' % (cmd, data))

@asyncio.coroutine
def _test_coro(client):
    """
    Test using client inside a coroutine.
    """
    cmd = 'show mode'
    result = yield from client.exec_cmd(cmd)
    _single_line_cmd_output(cmd, result)

    def quitter(cmd, data): # pylint: disable=unused-argument
        """
        Close the connection :o
        """
        client.close()
        client.exec_cmd_callback('show run ssh timeout', _single_line_cmd_output)

    client.exec_cmd_callback('show vpn-sessiondb', _multi_line_cmd_output)
    client.exec_cmd_callback('show run ssh timeout', quitter)

def main():
    """
    Test some stuff.
    """
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.get_event_loop()
    client = CiscoSSHClient(sys.argv[1], sys.argv[2], sys.argv[3], loop)

    loop.create_task(_test_coro(client))
    cmds = (
        ('show clock', _single_line_cmd_output),
        ('show run ip address', _multi_line_cmd_output),
        ('show firewall', _single_line_cmd_output)
    )
    for cmd, printer in cmds:
        client.exec_cmd_callback(cmd, printer)

    # Assuming SSH timeout is 5 minutes, run this at six minutes to test reconnecting.
    loop.call_later(60*6, lambda: client.exec_cmd_callback('show clock', _single_line_cmd_output))
    loop.run_forever()

if __name__ == '__main__':
    import sys
    main()
