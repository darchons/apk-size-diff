#!/usr/bin/env python

from ctypes import *
from ctypes.util import find_library

import io
import struct

def _bcj_filter_thumb(buf, offset, chunkSize, unfilter):
    end = offset

    while end < len(buf):
        i = end
        end = min(len(buf), end + chunkSize)

        while (i + 4) <= end:
            if (buf[i + 1] & 0xf8) != 0xf0 or (buf[i + 3] & 0xf8) != 0xf8:
                i += 2
                continue

            src = ((int(buf[i]) << 11)
                | (int(buf[i + 1] & 0x07) << 19)
                | int(buf[i + 2])
                | (int(buf[i + 3] & 0x07) << 8)) << 1

            if unfilter:
                dest = (src - i - 4) >> 1;
            else:
                dest = (i + 4 + src) >> 1;

            buf[i] = (dest >> 11) & 0xff
            buf[i + 1] = 0xf0 | ((dest >> 19) & 0x07)
            buf[i + 2] = dest & 0xff
            buf[i + 3] = 0xf8 | ((dest >> 8) & 0x07)
            i += 4

    return buf

def _bcj_filter_arm(buf, offset, chunkSize, unfilter):
    end = offset

    while end < len(buf):
        i = end
        end = min(len(buf), end + chunkSize)

        while (i + 4) <= end:
            if buf[i + 3] != 0xeb:
                i += 4
                continue

            src = (int(buf[i])
                | (int(buf[i + 1]) << 8)
                | (int(buf[i + 2]) << 16)) << 2

            if unfilter:
                dest = (src - i - 8) >> 2
            else:
                dest = (i + 8 + src) >> 2

            buf[i] = dest & 0xff;
            buf[i + 1] = (dest >> 8) & 0xff;
            buf[i + 2] = (dest >> 16) & 0xff;
            i += 4

    return buf

libz = CDLL(find_library('z'))

class ZStream(Structure):
    _fields_ = [
        ('next_in', POINTER(c_byte)),
        ('avail_in', c_uint),
        ('total_in', c_ulong),

        ('next_out', POINTER(c_byte)),
        ('avail_out', c_uint),
        ('total_out', c_ulong),

        ('msg', c_char_p),
        ('state', c_void_p),

        ('zalloc', c_void_p),
        ('zfree', c_void_p),
        ('opaque', c_void_p),

        ('data_type', c_int),
        ('adler', c_ulong),
        ('reserved', c_ulong),
    ]

libz.inflateInit2_.argtypes = [POINTER(ZStream), c_int, c_char_p, c_int]
libz.inflateSetDictionary.argtypes = [POINTER(ZStream), POINTER(c_byte), c_uint]
libz.inflate.argtypes = [POINTER(ZStream), c_int]
libz.inflateReset.argtypes = [POINTER(ZStream)]
libz.inflateEnd.argtypes = [POINTER(ZStream)]

Z_OK = 0
Z_STREAM_END = 1
Z_FINISH = 4

class SZipFile(object):
    def __init__(self, f):

        self._file = f
        self._passthru = False

        fmt = '<L'
        magic = f.peek(struct.calcsize(fmt))
        (magic,) = struct.unpack(fmt, magic[0: struct.calcsize(fmt)])

        if magic == 0x464c457f:
            # regular ELF file
            if not f.seekable():
                self._file = io.BytesIO(f.read())
            self._passthru = True
            return

        assert magic == 0x7a5a6553

        fmt = '<LLHHLHbB'
        (magic, totalSize, self._chunkSize, dictSize,
                self._nChunks, self._lastChunkSize, self._windowBits, self._filt
                ) = struct.unpack(fmt, f.read(struct.calcsize(fmt)))

        self._dictionary = (c_byte * dictSize).from_buffer_copy(
                f.read(dictSize)) if dictSize else None

        fmt = '<' + str(self._nChunks) + 'L'
        self._offsets = struct.unpack(fmt, f.read(struct.calcsize(fmt)))

        self._outSize = (self._nChunks - 1) * self._chunkSize + self._lastChunkSize
        self._buffer = bytearray()
        self._index = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        self._file.close()

    def _ensure(self, size):
        if len(self._buffer) >= size:
            return

        chunkSize = self._chunkSize
        oldSize = len(self._buffer)
        oldChunk = (oldSize + chunkSize - 1) // chunkSize
        newChunk = (size + chunkSize - 1) // chunkSize
        newSize = min(self._outSize, newChunk * chunkSize)

        self._buffer.extend(bytearray(newSize - oldSize))

        zstream = ZStream()
        zstream.zalloc = None
        zstream.zfree = None
        zstream.opaque = None

        for i in range(oldChunk, newChunk):
            if i < self._nChunks - 1:
                data = self._file.read(self._offsets[i + 1] - self._offsets[i])
            else:
                data = self._file.read()

            zstream.next_in = (c_byte * len(data)).from_buffer_copy(data)
            zstream.avail_in = len(data)

            start = i * chunkSize
            zstream.next_out = (c_byte * min(chunkSize, newSize - start)
                    ).from_buffer(self._buffer, start)
            zstream.avail_out = chunkSize

            if i != oldChunk:
                if libz.inflateReset(byref(zstream)) != Z_OK:
                    raise Exception('zlib: ' + zstream.msg.decode('utf-8'))
            else:
                if libz.inflateInit2_(byref(zstream), self._windowBits,
                                      b"1.2.8", sizeof(zstream)) != Z_OK:
                    raise Exception('zlib: initialization failed')

            if self._dictionary:
                if libz.inflateSetDictionary(byref(zstream), self._dictionary,
                                             len(self._dictionary)) != Z_OK:
                    raise Exception('zlib: ' + zstream.msg.decode('utf-8'))

            if libz.inflate(byref(zstream), Z_FINISH) != Z_STREAM_END:
                raise Exception('zlib: ' + zstream.msg.decode('utf-8'))

        if libz.inflateEnd(byref(zstream)) != Z_OK:
            raise Exception('zlib: ' + zstream.msg.decode('utf-8'))

        if self._filt == 1:
            _bcj_filter_thumb(self._buffer, oldSize, chunkSize, unfilter=True)
        elif self._filt == 2:
            _bcj_filter_arm(self._buffer, oldSize, chunkSize, unfilter=True)
        else:
            assert self._filt == 0

    def read(self, size=-1):
        if self._passthru:
            return self._file.read(size)

        if self._index >= self._outSize:
            raise EOFError()

        end = min(self._outSize, self._outSize if size < 0 else self._index + size)
        self._ensure(end)

        out = self._buffer[self._index: end]
        self._index += len(out)
        return out

    def read1(self, size=-1):
        if self._passthru:
            return self._file.read1(size)

        return self.read(size)

    def tell(self):
        if self._passthru:
            return self._file.tell()

        return self._index

    def seekable(self):
        if self._passthru:
            return self._file.seekable()

        return True

    def seek(self, offset, whence=0):
        if self._passthru:
            return self._file.seek(offset, whence)

        if whence == io.SEEK_CUR:
            offset += self._index
        elif whence == io.SEEK_END:
            offset += self._outSize

        self._index = max(0, min(self._outSize, offset))
        return self._index

if __name__ == '__main__':
    import sys

    with SZipFile(open(sys.argv[1], 'rb')) as infile:
        with open(sys.argv[2], 'wb') as outfile:
            outfile.write(infile.read())

