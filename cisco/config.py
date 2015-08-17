import logging
import os
import re
import time

__ALL__ = ['ConfigManager']

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

class ConfigManager(object):
    def __init__(self, manager, context):
        self._context = context
        self._manager = manager

        log_name = '%s(%s)' % (self.__class__.__name__, self._context.name)
        self.log = logging.getLogger(log_name)

        self._configs = [_ManagedConfig(self, context, None)]

        # This is somewhat dirty...
        if self._context.is_admin and self._context.sys_conn:
            self._configs.append(_ManagedConfig(self, self._context.sys_conn, None))

        self._manager.subscribe(manager.LOG_EVENT, '5-111008', self._cmd_run_event)
        self.check_config()

    def config_updated(self):
        self.log.debug('Config updated')
        self._manager.publish(self._manager, self._manager.CONFIG_EVENT, 'updated', None)

    def check_config(self):
        for config in self._configs:
            config.check()

    def _cmd_run_event(self, msg):
        IGNORED_USERS = ['failover']
        IGNORED_COMMANDS = ['changeto ', 'perfmon interval', 'copy ', 'show ',
                            'ping ', 'enable ', 'configure ']

        result = re.match("^User '([^']+)' executed the '([^']+)' command\.$", msg)
        if not result:
            return

        user, cmd = result.groups()
        for ignored in IGNORED_COMMANDS:
            if cmd.startswith(ignored):
                return

        for ignored in IGNORED_USERS:
            if ignored == user:
                return

        self.log.debug("command: %s => %s", user, cmd)

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

