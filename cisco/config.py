import logging
import os
import time
import re
import time
from hashlib import md5

from ..util.plugin import load_class

__ALL__ = ['ConfigManager']

class _NullFileDiff(object):
    """
    Represents a diff (or not) to a file. If there is no diff, self._diff is
    None. The diff can be committed to some storage backend with self.commit

    For testing only: This does not do anything.

    I don't even know what a diff object would actually be if there were
    actually diff objects. Perplexing.
    """
    def __init__(self, commit_cb, diff):
        self._commit = commit_cb
        self._diff = diff

    def commit(self, user, email,  msg):
        self._commit(user, email,  msg)

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

        commit_callback = lambda user, email, msg: self.commit(file_name, user, email, msg)
        file_diff = True if self._hash != oldhash else None
        diff = _NullFileDiff(commit_callback, file_diff)

        callback(diff)

    def commit(self, file_name, user, msg):
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

        self._store = None

        # Some backing store where we save the config
        if store is not None:
            name, cls = load_class(store['class'])
            if cls is not None:
                self._store = cls(**store['args'])

        # TODO: should I keep this here?
        if self._store is None:
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
    def __init__(self, manager, context, **kwargs):
        self._context = context
        self._manager = manager
        self._changes = []
        self._flushed_changes = []


        log_name = '%s(%s)' % (self.__class__.__name__, self._context.name)
        self.log = logging.getLogger(log_name)

        store = kwargs.get('store', None)
        self._configs = [_ManagedConfig(self, context, store)]

        # This is somewhat dirty...
        if self._context.is_admin and self._context.sys_conn:
            self._configs.append(_ManagedConfig(self, self._context.sys_conn, store))

        self._tags = kwargs.get('tags', [])
        self._load_user_map(kwargs.get('user_map', {}))

        self._manager.subscribe(manager.LOG_EVENT, '5-111008', self._cmd_run_event)
        self.check_config()

    def config_updated(self, diff):
        self.log.debug('Config updated')

        # @TODO: could publish another event for commit and include a diff...
        user, email, msg = self._get_commit_log(diff)
        self.log.debug('Committing changes: %s', msg)

        diff.commit(user, email, msg)
        self._manager.publish(self._manager.CONFIG_EVENT, 'updated')

    def check_config(self):
        for config in self._configs:
            config.check()

    def _get_commit_log(self, diff):
        users = set()
        changes = []

        tags = self._tag_diff(diff.diff)

        for cmd_time, user, cmd in self._flushed_changes:
            tm = time.strftime('%Y-%m-%d %H:%M:%S %Z', cmd_time)
            changes.append('%s[%s](%s): %s' % (tm, self._context.name, user, cmd))
            users.add(user)

        self._flushed_changes = []

        if users:
            # TODO: for system context, "Changes to ____" is wrong (who gives a fuck though?).
            hdr = '%sChanges to %s by %s' % (tags, self._context.name, ', '.join(users))
            user, email = self._get_mapped_user(users.pop())
        else:
            hdr = '%sChanges to %s' % (tags, self._context.name)
            user, email = self._get_mapped_user('backup')

        return user, email, (hdr + (os.linesep*2) + os.linesep.join(changes))

    def _load_user_map(self, user_map):
        self._user_map = {}
        for user in user_map:
            user_str = user_map[user]
            result = re.match('^(.+) <([^>]+)>', user_str)
            if result:
                self._user_map[user] = result.groups()

    def _get_mapped_user(self, user):
        if user in self._user_map:
            return self._user_map[name]
        elif '_default' in self._user_map:
            def_user, suffix = self._user_map['_default']
            return user, '%s@%s' % (user, suffix)
        else:
            return 'backup', 'backup@configure.me'

    def _tag_diff(self, diff):
        tags = set()

        for line in diff.splitlines():
            for tag in self._tags:
                result = re.match('.*(%s)' % tag, line)
                if result:
                    tags.add(result.group(1))
        if tags:
            return ', '.join(tags) + ' '
        else:
            return ''

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

