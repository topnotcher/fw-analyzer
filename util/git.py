import threading
import logging
import git
import os
import threading
import queue


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

    def commit(self, user, email, msg):
        self._commit(user, email, msg)

    @property
    def diff(self):
        return self._diff

    @property
    def changed(self):
        return self._diff is not None

class _GitRepoRequest(object):
    def __init__(self, store):
        self._store = store

    def service(self, repo):
        raise NotImplementedError

    def run_callback(self, callback, *args):
        self._store.loop.call_soon_threadsafe(callback, *args)

class _GitRepoCommitRequest(_GitRepoRequest):
    def __init__(self, store, actor, file_name, msg):
        super(_GitRepoCommitRequest, self).__init__(store)

        self._actor = actor
        self._file_name = file_name
        self._msg = msg

    def service(self, repo):
        file_path = os.path.join(repo.working_tree_dir, self._file_name)
        repo.index.add([file_path])
        repo.index.commit(author=self._actor, committer=self._actor, message=self._msg) 

class _GitRepoUpdateRequest(_GitRepoRequest):
    def __init__(self, store, file_name, content, callback):
        super(_GitRepoUpdateRequest, self).__init__(store)

        self._file_name = file_name
        self._content = content
        self._callback = callback

    def service(self, repo):
        # 1. Save file.
        file_path = os.path.join(repo.working_tree_dir, self._file_name)

        with open(file_path, 'w', encoding='utf8') as fh:
            fh.write(self._content)

        # 2. TODO: Get a diff of the file.
        commit_cb = lambda user, email, msg: self._store.commit(user, email, self._file_name, msg)
        diff = _NullFileDiff(commit_cb, True)

        # 3. Send the diff!
        self.run_callback(self._callback, diff)

class _GitRepoWorker(threading.Thread):
    def __init__(self, path, push=None):
        super(_GitRepoWorker, self).__init__()

        self.log = logging.getLogger(self.__class__.__name__)
        
        # This is probably going to block, but ehh it's init. Shush.
        self._repo = git.Repo(path)
        assert not self._repo.bare

        self._running = True
        self._queue = queue.Queue()
    
    def run(self):
        while self._running:
            self._work()

    def _work(self):
       request = self._queue.get()     
       request.service(self._repo)

    def put(self, req):
        self._queue.put(req)

class GitFileStore(object):
    def __init__(self, loop, path, push=None):
        self._worker = _GitRepoWorker(path, push)
        self._loop = loop
        self._worker.start()

    def update_file(self, file_name, content, callback):
        """
        Update the contents of a file on disk.

        :param file_name: The file name to update, relative to this repository.
        :param content: The content to put in the file.
        :param callback: A callback to call with a diff object.
        """
        req = _GitRepoUpdateRequest(self, file_name, content, callback)
        self._worker.put(req)
    
    @property
    def loop(self):
        return self._loop

    def commit(self, user, email, file_name, msg):
        """
        Commit all changes to a file.

        :param user: The user who made the changes.
        :param email: user's email address.
        :param file_name: The file to commit.
        :param msg: The commit message.
        """
        actor = git.Actor(user, email)
        req = _GitRepoCommitRequest(self, actor, file_name, msg)
        self._worker.put(req)
