import logging
import os
import time
import re
import time
from hashlib import md5

__ALL__ = ['ConfigManager']

class _NullFileDiff(object):
    def __init__(self, commit_cb, diff):
        self._commit = commit_cb
        self._diff = diff

    def commit(self, msg):
        self._commit(msg)

    @property
    def diff(self):
        return self._diff

    @property
    def changed(self):
        return self._diff is not None

class _NullFileStore(object):
    """
    For testing only: this does not even save files...
    """
    def __init__(self):
        self._hash = None

    def update_file(self, file_name, content, callback):
        """ true if file changes """
        oldhash = self._hash

        # TODO: if I didn't decode in SSH Client...
        self._hash = md5(content.encode('utf8'))

        commit_callback = lambda msg: self.commit(file_name, msg)
        file_diff = True if self._hash != oldhash else None
        diff = _NullFileDiff(commit_callback, file_diff)

        callback(diff)

    def commit(self, name, msg):
        pass

class _ManagedConfig(object):
    """
    Manage the configuration of a single context.
    """

    def __init__(self, config_manager, context, store=None):
        # timestamp the config was last retrieved
        self._config_timestamp = 0
        self._context = context
        self._config_manager = config_manager

        # Some backing store where we save the config
        if store is not None:
            self._store = store
        else:
            self._store = _NullFileStore()

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

        def updated_cb(diff):
            if diff.changed: self._config_manager.config_updated(diff)

        file_name = self._context.name
        self._store.update_file(file_name, config, updated_cb)

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
        self._changes = []
        self._flushed_changes = []

        log_name = '%s(%s)' % (self.__class__.__name__, self._context.name)
        self.log = logging.getLogger(log_name)

        self._configs = [_ManagedConfig(self, context, None)]

        # This is somewhat dirty...
        if self._context.is_admin and self._context.sys_conn:
            self._configs.append(_ManagedConfig(self, self._context.sys_conn, None))

        self._manager.subscribe(manager.LOG_EVENT, '5-111008', self._cmd_run_event)
        self.check_config()

    def config_updated(self, diff):
        self.log.debug('Config updated')

        # @TODO: could publish another event for commit and include a diff...
        msg = self._get_commit_msg()
        self.log.debug('Committing changes: %s', msg)

        diff.commit(msg)
        self._manager.publish(self._manager.CONFIG_EVENT, 'updated')

    def check_config(self):
        for config in self._configs:
            config.check()

    def _get_commit_msg(self):
        users = set()
        changes = []

        for cmd_time, user, cmd in self._flushed_changes:
            tm = time.strftime('%Y-%m-%d %H:%M:%S %Z', cmd_time)
            changes.append('%s[%s](%s): %s' % (tm, self._context.name, user, cmd))
            users.add(user)

        self._flushed_changes = []

        # TODO: for system context, "Changes to ____" is wrong.
        # TODO: ISSUE FUCKING TAGGING???????????????????????
        #       - Which we can now do given config_updated() receives some kind of diffy object
        hdr = 'Changes to %s by %s' % (self._context.name, ', '.join(users))

        return hdr + (os.linesep*2) + os.linesep.join(changes)

    def _cmd_run_event(self, cmd_time, msg):
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
        self._changes.append((cmd_time, user, cmd))

        # TODO: NEED TO HANDLE TIMEOUTS
        if cmd == 'write memory':
            self._flush_changes()

    def _flush_changes(self):
        # This needs to be done immediately: It is possible that we have queued
        # commands, but no diff in the config -- in this case the changes never
        # get flushed because config_updated() is not called.
        self._flushed_changes = self._changes
        self._changes = []
        self.check_config()

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

