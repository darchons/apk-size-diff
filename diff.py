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

def diff_zip(a, b, prefix=''):

    def _diff_file(name, asize, bsize):
        ext = name.rpartition('.')[-1]

        if ext in {'zip', 'apk', 'jar', 'ja'}:
            with ZipFile(BytesIO(a.read(name))) as azip:
                with ZipFile(BytesIO(b.read(name))) as bzip:
                    for diff in diff_zip(azip, bzip, prefix=(name + '/')):
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
            for diff in diff_zip(azip, bzip):
                print(diff)

