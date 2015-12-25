#!/usr/bin/env python

from io import BytesIO
from zipfile import ZipFile

import struct

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

def _dex_handler(name, a, b):

    def _get_size_map(f):
        data = f.read()
        sizes = dict()

        fmt = '<8s 28x LL L4x L LL LL 24x LL L'
        (magic, header_size, endian, link_size, map_off,
                strid_size, strid_off, typeid_size, typeid_off,
                class_size, class_off, data_size
                ) = struct.unpack(fmt, data[0: struct.calcsize(fmt)])

        assert magic == b'dex\n035\0'
        assert header_size == 0x70
        assert endian == 0x12345678
        NO_INDEX = 0xffffffff

        all_type_list_size = 0
        all_type_list_offs = set()

        def _get_type_list_size(off):
            if off in all_type_list_offs:
                return 0
            all_type_list_offs.add(off)
            (size,) = struct.unpack(
                    '<L', data[off: off + 4])
            return 4 + 2 * size

        def _get_str_by_id(strid, strid_off=strid_off):
            assert strid < strid_size
            off = strid_off + strid * 4
            (str_off,) = struct.unpack('<L', data[off: off + 4])
            return data[str_off: data.index(b'\0', str_off)]

        def _extract_str(s):
            for i, c in enumerate(s):
                if not (c & 0x80):
                    break
            return s[i + 1:]

        def _get_type_strid(typeid):
            assert typeid < typeid_size
            off = typeid_off + typeid * 4
            (strid,) = struct.unpack('<L', data[off: off + 4])
            return strid

        if map_off:
            map_infos = {
                # (name, size)
                # special case below for 0x0001: (b'.string', 0x04),
                0x0002: (b'.type', 0x04),
                # special case below for 0x0003: (b'.proto', 0x0c),
                0x0004: (b'.field', 0x08),
                0x0005: (b'.method', 0x08),
                0x0006: (b'.class', 0x20),
            }

            (map_size,) = struct.unpack('<L', data[map_off: map_off + 4])
            map_off += 4

            fmt = '<H 2x LL'
            fmt_size = struct.calcsize(fmt)

            for map_idx in range(map_off, map_off + map_size * 4, 4):
                item_type, item_count, item_off = struct.unpack(
                        fmt, data[map_idx: map_idx + fmt_size])

                if item_type == 0x0001: # string
                    size = 0
                    for strid in range(item_count):
                        str_size = len(_get_str_by_id(strid, item_off)) + 1
                        size += 4 + str_size
                        data_size -= str_size
                    sizes[b'.string'] = sizes.get(b'.string', 0) + size
                    continue

                if item_type == 0x0003: # proto
                    proto_fmt = '<' + '8xL' * item_count
                    proto_fmt_size = struct.calcsize(proto_fmt)
                    param_offs = struct.unpack(
                            proto_fmt, data[item_off: item_off + proto_fmt_size])
                    size = sum((_get_type_list_size(o) if o else 0)
                            for o in param_offs)
                    all_type_list_size += size
                    data_size -= size
                    sizes[b'.proto'] = sizes.get(b'.proto', 0) + item_count * 12
                    continue

                map_info = map_infos.get(item_type)
                if not map_info:
                    continue
                item_size = item_count * map_info[1]
                sizes[map_info[0]] = sizes.get(map_info[0], 0) + item_size

            sizes[b'.map'] = 4 + map_size * 12

        class_fmt = '<L 8x L L L L L'
        class_fmt_size = struct.calcsize(class_fmt)

        field_adjustment = 0
        method_adjustment = 0
        all_anno_size = 0
        all_anno_offs = set()

        for class_idx in range(class_off, class_off + class_size * 0x20, 0x20):
            size = 0x20
            (type_idx, ifce_off, src_idx, anno_off,
                    cdat_off, stat_off) = struct.unpack(
                    class_fmt, data[class_idx: class_idx + class_fmt_size])

            def _read_leb128(off, signed=False):
                val = 0
                for i in range(0, 32, 7):
                    datum = data[off]
                    off += 1
                    val |= int(datum & 0x7f) << i
                    if not (datum & 0x80):
                        if signed and datum & 0x40:
                            val |= -1 << (i + 7)
                        break
                return (val, off)

            def _read_enc_val(off):
                arg_type = data[off]
                off += 1
                if arg_type == 0x1c:
                    return _read_enc_array(off)
                elif arg_type == 0x1d:
                    return _read_enc_anno(off)
                elif arg_type == 0x1e or arg_type == 0x1f:
                    return off
                return off + (arg_type >> 5) + 1

            def _read_enc_array(off):
                size, off = _read_leb128(off)
                for i in range(size):
                    off = _read_enc_val(off)
                return off

            def _read_enc_anno(off):
                tmp, off = _read_leb128(off)
                size, off = _read_leb128(off)
                for i in range(size):
                    tmp, off = _read_leb128(off)
                    off = _read_enc_val(off)
                return off

            if ifce_off:
                ifce_size = _get_type_list_size(ifce_off)
                all_type_list_size += ifce_size
                data_size -= ifce_size

            if anno_off:
                anno_orig_off = anno_off

                fmt = '<LLLL'
                fmt_size = struct.calcsize(fmt)
                cls_anno_off, field_size, method_size, param_size = struct.unpack(
                        fmt, data[anno_off: anno_off + fmt_size])
                anno_off += fmt_size

                def _get_anno_item_size(off):
                    if off in all_anno_offs:
                        return 0
                    all_anno_offs.add(off)
                    return _read_enc_anno(off + 1) - off

                def _get_anno_set_size(off):
                    if off in all_anno_offs:
                        return 0
                    all_anno_offs.add(off)
                    (size,) = struct.unpack('<L', data[off: off + 4])
                    items = struct.unpack('<' + str(size) + 'L',
                            data[off + 4: off + size * 4 + 4])
                    return 4 + size * 4 + sum(
                            _get_anno_item_size(o) for o in items)

                def _get_anno_ref_size(off):
                    if off in all_anno_offs:
                        return 0
                    all_anno_offs.add(off)
                    (size,) = struct.unpack('<L', data[off: off + 4])
                    items = struct.unpack('<' + str(size) + 'L',
                            data[off + 4: off + size * 4 + 4])
                    return 4 + size * 4 + sum(
                            _get_anno_set_size(o) for o in items)

                fmt = '<' + '4xL' * field_size
                fmt_size = struct.calcsize(fmt)
                field_offs = struct.unpack(fmt, data[anno_off: anno_off + fmt_size])
                anno_off += fmt_size

                fmt = '<' + '4xL' * method_size
                fmt_size = struct.calcsize(fmt)
                method_offs = struct.unpack(fmt, data[anno_off: anno_off + fmt_size])
                anno_off += fmt_size

                fmt = '<' + '4xL' * param_size
                fmt_size = struct.calcsize(fmt)
                param_offs = struct.unpack(fmt, data[anno_off: anno_off + fmt_size])
                anno_off += fmt_size

                assert anno_off - anno_orig_off == 16 + (
                        field_size + method_size + param_size) * 8

                anno_size = anno_off - anno_orig_off
                anno_size += _get_anno_set_size(cls_anno_off) if cls_anno_off else 0
                anno_size += sum(_get_anno_set_size(o) for o in field_offs)
                anno_size += sum(_get_anno_set_size(o) for o in method_offs)
                anno_size += sum(_get_anno_ref_size(o) for o in param_offs)

                all_anno_size += anno_size
                data_size -= anno_size

            if cdat_off:
                cdat_orig_off = cdat_off
                sf_size, cdat_off = _read_leb128(cdat_off)
                if_size, cdat_off = _read_leb128(cdat_off)
                dm_size, cdat_off = _read_leb128(cdat_off)
                vm_size, cdat_off = _read_leb128(cdat_off)

                for i in range(sf_size + if_size):
                    tmp, cdat_off = _read_leb128(cdat_off)
                    tmp, cdat_off = _read_leb128(cdat_off)

                code_fmt = '<6x H L L'
                code_fmt_size = struct.calcsize(code_fmt)

                for i in range(dm_size + vm_size):
                    tmp, cdat_off = _read_leb128(cdat_off)
                    tmp, cdat_off = _read_leb128(cdat_off)
                    code_off, cdat_off = _read_leb128(cdat_off)

                    if not code_off:
                        continue

                    code_orig_off = code_off
                    tries_size, debug_off, insns_size = struct.unpack(
                            code_fmt, data[code_off: code_off + code_fmt_size])
                    code_off += code_fmt_size + tries_size * 8 + (insns_size +
                            ((insns_size & 1) if tries_size else 0)) * 2

                    if tries_size:
                        catch_list_size, code_off = _read_leb128(code_off)
                    else:
                        catch_list_size = 0

                    for j in range(catch_list_size):
                        catch_size, code_off = _read_leb128(code_off, True)
                        for k in range(abs(catch_size)):
                            tmp, code_off = _read_leb128(code_off)
                            tmp, code_off = _read_leb128(code_off)
                        if catch_size <= 0:
                            tmp, code_off = _read_leb128(code_off)

                    size += code_off - code_orig_off
                    data_size -= code_off - code_orig_off

                    if not debug_off:
                        continue

                    debug_orig_off = debug_off
                    tmp, debug_off = _read_leb128(debug_off)
                    param_size, debug_off = _read_leb128(debug_off)
                    for i in range(param_size):
                        tmp, debug_off = _read_leb128(debug_off)

                    bytecode_args = {
                        0x01: 1,
                        0x02: 1,
                        0x03: 3,
                        0x04: 4,
                        0x05: 1,
                        0x06: 1,
                        0x09: 1,
                    }
                    bytecode = data[debug_off]
                    debug_off += 1

                    while bytecode:
                        bytecode_arg = bytecode_args.get(bytecode, 0)
                        while bytecode_arg:
                            if not (data[debug_off] & 0x80):
                                bytecode_arg -= 1
                            debug_off += 1
                        bytecode = data[debug_off]
                        debug_off += 1

                    size += debug_off - debug_orig_off
                    data_size -= debug_off - debug_orig_off

                if stat_off:
                    stat_size = _read_enc_array(stat_off) - stat_off
                    size += stat_size
                    data_size -= stat_size

                field_adjustment += (sf_size + if_size) * 8
                size += (sf_size + if_size) * 8

                method_adjustment += (dm_size + vm_size) * 8
                size += (dm_size + vm_size) * 8

                size += cdat_off - cdat_orig_off
                data_size -= cdat_off - cdat_orig_off

            src_str = (_extract_str(_get_str_by_id(src_idx))
                    if src_idx != NO_INDEX else b'.class')
            sizes[src_str] = sizes.get(src_str, 0) + size

        if b'.field' in sizes:
            sizes[b'.field'] -= field_adjustment

        if b'.method' in sizes:
            sizes[b'.method'] -= method_adjustment

        sizes[b'.annotation'] = all_anno_size
        sizes[b'.typelist'] = all_type_list_size
        sizes[b'.data'] = data_size
        sizes[b'.link'] = link_size
        return sizes

    a_map = _get_size_map(a) if a else dict()
    b_map = _get_size_map(b) if b else dict()

    for map_name, b_size in b_map.items():
        a_size = a_map.pop(map_name, 0)
        if a_size != b_size:
            yield Diff(name + '/' + map_name.decode('utf-8'), a_size, b_size)

    for map_name, a_size in a_map.items():
        if a_size:
            yield Diff(name + '/' + map_name.decode('utf-8'), a_size, 0)

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
            'dex': _dex_handler,
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

