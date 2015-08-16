"""
Utilities for using asyncio to SSH into a Cisco ASA.
"""

import asyncssh
import asyncio
import os
import re
import logging

__ALL__ = ['CiscoSSHClient']

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
        self._cmd_done_callback(self.cmd, future.result())

    @property
    def cmd(self):
        """
        Return the command to be run.
        """
        return self._cmd

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

        self._conn = None
        self._stdin = None
        self._stdout = None
        self._linesep = b'\r\n'
        self._loop = loop

        # Connection idle timeout (client side)
        self._timeout = 180

        self.log = logging.getLogger(self.__class__.__name__)
        self._queue = asyncio.Queue(loop=self._loop)
        self._running = True
        self._task = self._loop.create_task(self._run())

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
        Queue a command for execution and send the output to a callback on completion.
        """
        self._queue_cmd(cmd, callback)

    def stop(self):
        """
        Stop the client from running. It is unusable after stopping.
        """
        self.close()
        self._running = False

    def connection_lost(self, exc=None):
        """
        Handle connection lost events - called automatically when a connection is lost.
        """
        self._stdin = None
        self._stdout = None
        self._conn = None

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
        if result and re.match('^.+> $', result[0]):
            yield from self._enable()

        self._send_cmd('terminal pager 0')
        yield from self.collect_until_prompt(b'^.+# ')

    @asyncio.coroutine
    def _enable(self):
        """
        enable: Enter privileged EXEC mode.
        """
        echo_size = self._send_cmd('enable')
        result = yield from self.collect_until_prompt(b'Password: ', ignore_echo=echo_size)

        # TODO: None case not handled
        if result is not None:
            self._send_cmd(self._login['password'])
            yield from self.collect_until_prompt(b'^.+# ')

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
                last_line = get_last_line(buf, self._linesep)
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

        match_prompt = b'^.+# '
        result = yield from self.collect_until_prompt(match_prompt, ignore_echo=echo_size)

        if not result:
            return None
        else:
            return result[1]

def get_last_line(buf, sep):
    """
    Get the last line of a buffer.
    """
    pos = buf.rfind(sep)
    if pos == -1:
        return buf
    else:
        return buf[pos + len(sep):]

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
