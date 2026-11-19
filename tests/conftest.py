import struct
import pytest


@pytest.fixture
def inert_pe():
    """Minimal valid PE container with a zero-filled data section, never executed."""
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH',data,0x84,0x14c,1,0,0,0,224,0x102)
    start = 0x98
    struct.pack_into('<H',data,start,0x10b)
    struct.pack_into('<III',data,start+4,0,512,0)
    struct.pack_into('<III',data,start+16,0,0x1000,0x1000)
    struct.pack_into('<III',data,start+28,0x400000,0x1000,0x200)
    struct.pack_into('<HH',data,start+40,6,0)
    struct.pack_into('<III',data,start+56,0x2000,0x200,0)
    struct.pack_into('<HH',data,start+68,3,0x140)
    struct.pack_into('<IIIIII',data,start+72,0x100000,0x1000,0x100000,0x1000,0,16)
    section = start+224
    data[section:section+8] = b'.data\0\0\0'
    struct.pack_into('<IIIIIIHHI',data,section+8,512,0x1000,512,512,0,0,0,0,0x40000040)
    return bytes(data)


@pytest.fixture
def record(inert_pe):
    from malguard.scanner import scan
    return scan(inert_pe,'fixture.exe')


@pytest.fixture
def store(tmp_path):
    from malguard.storage import Store
    result = Store('sqlite:///'+(tmp_path/'history.db').as_posix())
    yield result
    result.engine.dispose()
