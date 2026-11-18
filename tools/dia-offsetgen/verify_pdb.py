import os
import pathlib
import struct
import sys
import uuid

KERNEL = os.environ.get("NANAHIRA_NTOSKRNL", r"C:\Windows\System32\ntoskrnl.exe")
PDB = sys.argv[1] if len(sys.argv) > 1 else r"D:\Ameger\Mapper\Build\Symbols\ntkrnlmp.pdb"

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]

def rva_to_off(b, rva):
    e = u32(b, 0x3c)
    nsec = u16(b, e + 6)
    optsz = u16(b, e + 20)
    sec = e + 24 + optsz
    for i in range(nsec):
        s = sec + i * 40
        va = u32(b, s + 12)
        vs = u32(b, s + 8)
        raw = u32(b, s + 20)
        if va <= rva < va + max(vs, u32(b, s + 16)):
            return raw + (rva - va)
    raise ValueError(f"rva not mapped: {rva:x}")

def pe_codeview(path):
    b = pathlib.Path(path).read_bytes()
    e = u32(b, 0x3c)
    assert b[e:e+4] == b"PE\0\0", "not PE"
    magic = u16(b, e + 24)
    dd = e + 24 + (112 if magic == 0x20b else 96)
    dbg_rva, dbg_sz = u32(b, dd + 6 * 8), u32(b, dd + 6 * 8 + 4)
    off = rva_to_off(b, dbg_rva)
    for i in range(dbg_sz // 28):
        d = off + i * 28
        if u32(b, d + 12) == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            cv = rva_to_off(b, u32(b, d + 24))
            assert b[cv:cv+4] == b"RSDS", b[cv:cv+4]
            g = b[cv+4:cv+20]
            guid = str(uuid.UUID(bytes_le=g)).upper()
            age = u32(b, cv + 20)
            end = b.find(b"\0", cv + 24)
            pdb_path = b[cv+24:end].decode("utf-8", "replace")
            return guid, age, pdb_path
    raise ValueError("no CodeView record")

def pdb_guid(path):
    b = pathlib.Path(path).read_bytes()
    assert b[:32] == b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", b[:32]
    block = u32(b, 32)
    dirbytes = u32(b, 44)
    dirblock = u32(b, 52)  # BlockMapAddr; offset 48 is reserved/Unknown
    nblocks_dir = (dirbytes + block - 1) // block
    dirdata = b"".join(b[bl*block:(bl+1)*block] for bl in
                       struct.unpack_from(f"<{nblocks_dir}I", b, dirblock*block))
    nstreams = u32(dirdata, 0)
    sizes = [u32(dirdata, 4 + 4*i) for i in range(nstreams)]
    pos = 4 + 4*nstreams
    streams = []
    for sz in sizes:
        cnt = 0 if sz == 0xFFFFFFFF else (sz + block - 1)//block
        blocks = struct.unpack_from(f"<{cnt}I", dirdata, pos)
        pos += 4*cnt
        streams.append(blocks)
    s1 = b"".join(b[bl*block:(bl+1)*block] for bl in streams[1])
    version = u32(s1, 0)
    age = u32(s1, 8)
    guid = str(uuid.UUID(bytes_le=s1[12:28])).upper()
    return guid, age, version

kguid, kage, kpath = pe_codeview(KERNEL)
pguid, page, pver = pdb_guid(PDB)
print("kernel PDB path :", kpath)
print("kernel GUID     :", kguid, "age", kage)
print("given PDB GUID  :", pguid, "age", page, "format", pver)
# Microsoft redistributed PDBs may carry a different internal age than the
# CodeView record in the PE. The GUID is the stable identity; match on that.
if kguid != pguid:
    print("MATCH           : False  <-- WRONG PDB, refusing to generate offsets")
    sys.exit(1)
print("MATCH           : True")
