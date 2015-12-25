#!/usr/bin/env python

from io import BytesIO
from zipfile import ZipFile

class Diff(object):
    def __init__(self, name, asize, bsize):
        self._name = name
        self._asize = asize
        self._bsize = bsize

    def __str__(self):
        if self._asize > self._bsize:
            # content deleted.
            return '-%d %s' % (self._asize - self._bsize, self._name)
        # content added.
        return '+%d %s' % (self._bsize - self._asize, self._name)

class Differ(object):
    def __init__(self):
        def _zip_handler(name, a, b):
            if not a or not b:
                with ZipFile(BytesIO((a or b).read())) as zipf:
                    for diff in self._diff_zip(zipf if a else None,
                                               zipf if b else None,
                                               name + '/'):
                        yield diff
                return

            with ZipFile(BytesIO(a.read())) as azip:
                with ZipFile(BytesIO(b.read())) as bzip:
                    for diff in self._diff_zip(azip, bzip, name + '/'):
                        yield diff

        self._handlers = {
            'zip': _zip_handler,
            'apk': _zip_handler,
            'jar': _zip_handler,
            'ja':  _zip_handler,
        }

    def set_handler(self, ext, handler):
        self._handlers[ext] = handler

    def get_handler(self, ext):
        return self._handlers.get(ext)

    def diff_zip(self, a, b):
        with ZipFile(a) as azip:
            with ZipFile(b) as bzip:
                for diff in self._diff_zip(azip, bzip, ''):
                    yield diff

    def _diff_zip(self, a, b, prefix):

        def _diff_file(name, asize, bsize):
            ext = name.rpartition('.')[-1]
            handler = self._handlers.get(ext)

            if handler:
                for diff in handler(prefix + name,
                                    a.open(name) if asize else None,
                                    b.open(name) if bsize else None):
                    yield diff
                return

            if asize != bsize:
                yield Diff(prefix + name, asize, bsize)

        afiles = {info.filename: info for info in a.infolist()} if a else {}

        if b:
            for bfile in b.infolist():
                name = bfile.filename
                afile = afiles.pop(name, None)

                # File added or updated.
                for diff in _diff_file(name,
                                       afile.file_size if afile else 0,
                                       bfile.file_size):
                    yield diff

        for afile in afiles.values():
            # file deleted.
            for diff in _diff_file(afile.filename, afile.file_size, 0):
                yield diff

if __name__ == '__main__':
    import sys

    differ = Differ()
    for diff in differ.diff_zip(sys.argv[1], sys.argv[2]):
        print(diff)

