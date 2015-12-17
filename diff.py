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
            with ZipFile(a) as azip:
                with ZipFile(b) as bzip:
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
        for diff in self._diff_zip(a, b, ''):
            yield diff

    def _diff_zip(self, a, b, prefix):

        def _diff_file(name, asize, bsize):
            ext = name.rpartition('.')[-1]
            handler = self._handlers.get(ext)

            if handler:
                for diff in handler(prefix + name,
                                    BytesIO(a.read(name)),
                                    BytesIO(b.read(name))):
                    yield diff
                return

            if asize != bsize:
                yield Diff(prefix + name, asize, bsize)

        afiles = {info.filename: info for info in a.infolist()}

        for bfile in b.infolist():
            name = bfile.filename
            afile = afiles.pop(name, None)

            if afile:
                # file updated.
                for diff in _diff_file(name, afile.file_size, bfile.file_size):
                    yield diff
                continue

            # file added.
            yield Diff(prefix + name, 0, bfile.file_size)

        for afile in afiles.values():
            # file deleted.
            yield Diff(prefix + afile.filename, afile.file_size, 0)

if __name__ == '__main__':
    import sys

    with ZipFile(sys.argv[1]) as azip:
        with ZipFile(sys.argv[2]) as bzip:
            differ = Differ()
            for diff in differ.diff_zip(azip, bzip):
                print(diff)

