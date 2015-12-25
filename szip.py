#!/usr/bin/env python

import io
import struct
import zlib

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
        (magic, totalSize, chunkSize, dictSize,
                nChunks, lastChunkSize, windowBits, filt
                ) = struct.unpack(fmt, f.read(struct.calcsize(fmt)))

        self._header = None

        if dictSize:
            dictionary = f.read(dictSize)
            if windowBits < 0:
                # Work around Python zlib bug of not properly setting dictionary
                # for raw inflate, by manually adding a header and tail to create a
                # full zlib stream
                self._header = struct.pack('>BBL', 0x78, 0xBB, zlib.adler32(dictionary))
                windowBits = -windowBits
            self._inflator = zlib.decompressobj(wbits=windowBits, zdict=dictionary)
        else:
            self._inflator = zlib.decompressobj(wbits=windowBits)

        fmt = '<' + str(nChunks) + 'L'
        self._offsets = struct.unpack(fmt, f.read(struct.calcsize(fmt)))

        self._outSize = (nChunks - 1) * chunkSize + lastChunkSize
        self._chunkSize = chunkSize
        self._nChunks = nChunks
        self._lastChunkSize = lastChunkSize
        self._filt = filt
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

        for i in range(oldChunk, newChunk):
            inflator = self._inflator.copy()

            if i < self._nChunks - 1:
                data = self._file.read(self._offsets[i + 1] - self._offsets[i])
            else:
                data = self._file.read()

            if self._header:
                data = self._header + data
                out = inflator.decompress(data)
                out = out + inflator.decompress(
                        struct.pack('>L', zlib.adler32(out))) + inflator.flush()
            else:
                out = inflator.decompress(data) + inflator.flush()

            start = i * chunkSize
            self._buffer[start: start + len(out)] = out

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

