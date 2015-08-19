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
    def __init__(self, store, actor, file_name, msg, push):
        super(_GitRepoCommitRequest, self).__init__(store)

        self._actor = actor
        self._file_name = file_name
        self._msg = msg
        self._push = push

    def service(self, repo):
        file_path = os.path.join(repo.working_tree_dir, self._file_name)
        repo.index.commit(author=self._actor, committer=self._actor, message=self._msg)

        if self._push:
            r_name, branch = self._push.split(' ')
            remote = getattr(remo.remotes, r_name)
            src_branch = repo.active_branch.name
            remote.push('%s:refs/heads/%s' % (src_branch, branch))

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

        repo.index.add([file_path])

        # 2. TODO: Get a diff of the file.
        commit_cb = lambda user, email, msg: self._store.commit(user, email, self._file_name, msg)

        diffs = repo.index.diff('HEAD', file_path, create_patch=True)
        if diffs and diffs[0]:
            diff = diffs[0].diff.decode('utf8')
        else:
             diff = None

        diff_obj = _NullFileDiff(commit_cb, diff)

        # 3. Send the diff!
        self.run_callback(self._callback, diff_obj)

class _GitWorkerStopRequest(_GitRepoRequest):
    def __init__(self, worker):
        self._worker = worker

    def service(self, repo): # pylint: disable=unused-arguments
        self._worker.cancel()

class _GitRepoWorker(threading.Thread):
    def __init__(self, path):
        super(_GitRepoWorker, self).__init__(name=self.__class__.__name__)

        self.log = logging.getLogger(self.__class__.__name__)

        # This is probably going to block, but ehh it's init. Shush.
        self._repo = git.Repo(path)
        assert not self._repo.bare

        self._queue = queue.Queue()
        self._running = threading.Event()
        self._running.set()

    def run(self):
        while self._running.is_set():
           request = self._queue.get()
           try:
               request.service(self._repo)
            except Exception as err:
                self.log.exception(err)

    def put(self, req):
        self._queue.put(req)

    # TODO: use this!
    def stop(self):
        # This will be the last request processed. All queued requests before
        # stop() will be processed()
        self.put(_GitWorkerStopRequest(self))
        self._worker.join()

    # Since the worker thread will be blocking on the Queue,
    # this will not cancel it until the next request is serviced.
    def cancel(self):
        self._running.clear()


class GitFileStore(object):
    """
    A very non-generalized limited use case helper for running some git
    operations in another thread so that they can be performed from an asyncio
    event loop.
    """
    def __init__(self, loop, path, push=None):
        self._worker = _GitRepoWorker(path)
        self._push = push
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
        req = _GitRepoCommitRequest(self, actor, file_name, msg, self._push)
        self._worker.put(req)
