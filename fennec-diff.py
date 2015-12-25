#!/usr/bin/env python

from diff import Diff, Differ
from io import BytesIO
from szip import SZipFile
from zipfile import ZipFile

import struct

def get_so_handler(asym, bsym):

    def _find_sym(symzip, name):
        basename = name.rpartition('/')[-1] + '/'
        for fn in symzip.namelist():
            if fn.startswith(basename):
                break
        return fn if fn.startswith(basename) else None

    def _add_sym_sizes(sym, sizes):

        total = 0
        srcnames = dict()

        for line in sym:
            if line.startswith(b'FILE '):
                # 'FILE filenum vcs:repo:file:commit'
                lineparts = line.strip().split(b' ')
                fileparts = lineparts[2].split(b':')
                if len(fileparts) < 4:
                    continue
                srcnames[lineparts[1]] = fileparts[2]
                sizes[fileparts[2]] = 0
                continue

            if line[0] in b'0123456789abcdef':
                # 'addr size line filenum'
                lineparts = line.strip().split(b' ')
                srcname = srcnames.get(lineparts[3])
                if not srcname:
                    continue
                diff = int(lineparts[1], 0x10)
                sizes[srcname] += diff
                total += diff
                continue

        return total

    def _add_elf_sizes(elf, sizes, text_size):
        fmt = '<LBB 26x L 10x HHH'
        (magic, bits, endian, shoff, shent, shnum, shstr
                ) = struct.unpack(fmt, elf.read(struct.calcsize(fmt)))

        assert magic == 0x464c457f
        assert bits == 1
        assert endian == 1

        sections = dict()

        elf.seek(shoff)
        for i in range(shnum):
            fmt = '<L 12x LL'
            fmt += str(shent - struct.calcsize(fmt)) + 'x'
            (shnameidx, shoff, shsize) = struct.unpack(
                    fmt, elf.read(struct.calcsize(fmt)))
            sections[shnameidx] = shsize

            if i == shstr:
                # extract string names
                shstroff = shoff
                shstrsize = shsize

        elf.seek(shstroff)
        shstr = elf.read(shstrsize)

        for shnameidx, shsize in sections.items():
            shnameend = shnameidx
            while shstr[shnameend]:
                shnameend += 1

            shname = bytes(shstr[shnameidx: shnameend])
            if shname == b'.text':
                shsize -= text_size

            sizes[shname] = shsize

    def _so_handler(name, a, b):
        asymsizes = dict()
        bsymsizes = dict()

        if a:
            asymtotal = 0
            with ZipFile(asym) as asymzip:
                symname = _find_sym(asymzip, name)
                if symname:
                    with asymzip.open(symname) as sym:
                        asymtotal = _add_sym_sizes(sym, asymsizes)

            with SZipFile(a) as aelf:
                _add_elf_sizes(aelf, asymsizes, asymtotal)

        if b:
            bsymtotal = 0
            with ZipFile(bsym) as bsymzip:
                symname = _find_sym(bsymzip, name)
                if symname:
                    with bsymzip.open(symname) as sym:
                        bsymtotal = _add_sym_sizes(sym, bsymsizes)

            with SZipFile(b) as belf:
                _add_elf_sizes(belf, bsymsizes, bsymtotal)

        for srcname, bsize in bsymsizes.items():
            asize = asymsizes.pop(srcname, 0)
            if asize != bsize:
                yield Diff(name + '/' + srcname.decode('utf-8'), asize, bsize)

        for srcname, asize in asymsizes.items():
            if asize:
                yield Diff(name + '/' + srcname.decode('utf-8'), asize, 0)

    return _so_handler

if __name__ == '__main__':
    import sys

    a, b = sys.argv[1:3]
    asym, bsym = (s.replace('.multi.', '.en-US.')
                   .replace('.apk', '.crashreporter-symbols.zip') for s in (a, b))

    differ = Differ()
    differ.set_handler('so', get_so_handler(asym, bsym))

    for diff in differ.diff_zip(a, b):
        print(diff)

