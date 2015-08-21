"""
Utilities for managing Cisco ASAs in single or multiple context mode.

In multiple context mode, all of the contexts can be managed by a single
:class:`CiscoFwManager` instance, which relies on a
:class:`MultiContextExecutor` instance to ensure that context commands are
executed in the appropriate context.
"""

__ALL__ = [
    'CiscoFwManager',
]

import asyncio
import re
import logging

from ..syslog import SyslogListener
from .client import CiscoSSHClient, enumerate_contexts
from ..util.plugin import load_class

class _CiscoFwContextManager(object):
    LOG_EVENT = 1
    CONFIG_EVENT = 2

    def __init__(self, context, loop):
        self._context = context
        self._loop = loop
        self._ips = []
        self._plugins = []

        log_name = '%s(%s)' % (self.__class__.__name__, self._context.name)
        self.log = logging.getLogger(log_name)

        #  NOTE: This does _not_ filter out addresses on down interfaces.
        self._context.exec_cmd_callback('show run ip address', self._populate_ips)

        self._subscribers = []

    @property
    def loop(self):
        return self._loop

    @property
    def name(self):
        return self._context.name

    def subscribe(self, topic, evt, callback):
        sub = (topic, evt, callback)
        self._subscribers.append(sub)

    def publish(self, topic, evt, *args, **kwargs):
        for sub_topic, sub_evt, sub_cb in self._subscribers:
            if sub_topic == topic and sub_evt == evt:
                sub_cb(*args, **kwargs)

    def add_plugin(self, plugin_class, **kwargs):
        ins = plugin_class(self, self._context, **kwargs)

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
        self.publish(self.LOG_EVENT, evt, time, msg)

class CiscoFwManager(SyslogListener):
    """
    Main class for FW management: determines firewall mode, enumerates
    contexts, etc.
    """
    def __init__(self, loop, **kwargs):
        self._loop = loop
        self._initialized = asyncio.Event(loop=self._loop)

        self._contexts = []
        self._is_multi_context = False

        self._plugin_config = kwargs.get('plugins', {})

        self.log = logging.getLogger(self.__class__.__name__)

        conn = CiscoSSHClient(kwargs['host'], kwargs['user'], kwargs['pass'], self._loop)
        self._loop.create_task(self._initialize(conn))

    @asyncio.coroutine
    def _initialize(self, conn):
        contexts = yield from enumerate_contexts(conn)

        num = len(contexts)
        if num > 1 or (num > 0 and contexts[0].is_admin):
            self._is_multi_context = True
        else:
            self._is_multi_context = False

        plugins = self._load_plugins(self._plugin_config)

        for context in contexts:
            try:
                self._init_context(context, plugins, self._plugin_config)
            except Exception as err:
                self.log.error('Error initializing _CisoFwContextManager(%s).', context.name)
                self.log.exception(err)

        self._initialized.set()

    def _init_context(self, context, plugins, args):
        context_mgr = _CiscoFwContextManager(context, self._loop)
        self._contexts.append(context_mgr)

        # initialize plugins for context manager
        for name in plugins:
            try:
                kwargs = args[name]
                if kwargs is not None:
                    context_mgr.add_plugin(plugins[name], **kwargs)
                else:
                    context_mgr.add_plugin(plugins[name])
            except Exception as err:
                self.log.error('Error initializing plugin class "%s".', name)
                self.log.exception(err)

    def _load_plugins(self, plugin_classes):
        plugins = map(load_class, plugin_classes)
        loaded_plugins = {}

        for name, cls in plugins:
            if not cls:
                self.log.error('Could not find plugin class "%s".', name)
            else:
                self.log.info('Loaded plugin class: "%s".', name)
                loaded_plugins[name] = cls

        return loaded_plugins

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
        if not self._initialized.is_set():
            return

        for context in self._contexts:
            ip = src.decode('utf8')
            if context.has_ip(ip):
                self.log.info('%s has IP %s', context.name, ip)

                msg = msg.decode('utf8')
                parsed = self._parse_log(msg)

                if parsed:
                    context.handle_log_event(time, parsed[0], parsed[1])
                else:
                    self.log.debug('Failed to parse "%s"', msg)

    @staticmethod
    def _parse_log(log):
        """
        Parse a Cisco log message into the event ID and the message.

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
