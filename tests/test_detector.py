"""Synthetic PE tests and optional tests of locally supplied releases."""
import os
from pathlib import Path
import random
import struct
import unittest
import contextlib
import io
import tempfile
from types import SimpleNamespace

import patch_dgvoodoo as p


def fixture(seed=1, matcher=0x300, base=0x10000000):
    """Assemble an x86 predicate and module/export caller with random keys."""
    rng = random.Random(seed)
    d = bytearray(0x2400)
    d[:2] = b'MZ'
    struct.pack_into('<I', d, 0x3c, 0x80)
    d[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', d, 0x84, 0x14c, 2)
    struct.pack_into('<H', d, 0x94, 0xe0)
    struct.pack_into('<H', d, 0x98, 0x10b)
    struct.pack_into('<I', d, 0xb4, base)
    for n, (rva, raw, flags) in enumerate(((0x1000, 0x400, 0x60000020),
                                         (0x3000, 0x1400, 0x40000040))):
        o = 0x178 + 40 * n
        struct.pack_into('<IIII', d, o + 8, 0x1000, rva, 0x1000, raw)
        struct.pack_into('<I', d, o + 36, flags)
    u32 = lambda value: struct.pack('<I', value & 0xffffffff)
    addr = lambda off: base + 0x1000 + off
    key1, key2, name_key, stored = (base + 0x3000 + n for n in (0, 4, 0x20, 0x80))
    keys = [rng.randrange(0x10000) for _ in range(9)]
    encoded = struct.pack('<9H', *((ord(c) - k) & 0xffff for c, k in zip('NTDLL.DLL', keys)))
    struct.pack_into('<9H', d, 0x1420, *keys)
    k1, k2 = rng.getrandbits(32), rng.getrandbits(32)
    struct.pack_into('<II', d, 0x1400, k1, k2)
    caller = bytearray()
    for n in range(0, 16, 4):
        caller += b'\xc7\x05' + u32(stored + n) + encoded[n:n + 4]
    caller += b'\xb8' + encoded[16:] + b'\0\0\x66\xa3' + u32(stored + 16)
    caller += b'\x0f\xb7\x34\x7d' + u32(name_key)
    caller += b'\x66\x2b\xc6\x66\x3b\x04\x7d' + u32(stored)
    # e_lfanew, export directory/size, AddressOfNames, NumberOfNames.
    caller += bytes.fromhex('8b473c03c78b507883787c0003d78b722003f73b4a188b049e')
    call = addr(0x40 + len(caller))
    caller += b'\xe8' + struct.pack('<i', addr(matcher) - call - 5) + b'\xc3'
    d[0x440:0x440 + len(caller)] = caller
    code, labels, fixups = bytearray(), {}, []

    def branch(op, label):
        code.extend(bytes([op, 0]))
        fixups.append((len(code) - 1, label))

    code += bytes.fromhex('83f808')
    branch(0x72, 'fail')
    code += bytes.fromhex('8d70f833d2')
    labels['scan'] = len(code)
    code += b'\x8b\x0d' + u32(key1) + bytes.fromhex('8b043a03c881f9')
    code += u32(k1 + int.from_bytes(b'wine', 'little'))
    branch(0x75, 'loop')
    code += b'\x8b\x0d' + u32(key2) + bytes.fromhex('8b443a0403c881f9')
    code += u32(k2 + int.from_bytes(b'_get', 'little'))
    branch(0x74, 'success')
    patch_offset = 0x400 + matcher + len(code) - 1
    labels['loop'] = len(code)
    code += bytes.fromhex('423bd6')
    branch(0x72, 'scan')
    labels['fail'] = len(code)
    code += bytes.fromhex('32c0c3')
    labels['success'] = len(code)
    code += bytes.fromhex('b001c3')
    for off, label in fixups:
        code[off] = (labels[label] - off - 1) & 255
    d[0x400 + matcher:0x400 + matcher + len(code)] = code
    return d, patch_offset


class SemanticTests(unittest.TestCase):
    def test_random_keys_locations_and_bases(self):
        for seed in range(10):
            with self.subTest(seed=seed):
                d, off = fixture(seed, 0x300 + seed * 32, 0x20000000 + seed * 0x100000)
                self.assertEqual([s.offset for s in p.find_sites(d)], [off])
                before = bytes(d)
                self.assertEqual(p.patch(d), [(off, before[off], 0)])
                self.assertEqual([i for i, (a, b) in enumerate(zip(before, d)) if a != b], [off])
                self.assertTrue(p.already_patched(d))
                self.assertEqual(p.patch(d), [])

    def test_detached_predicate_is_ignored(self):
        d, _ = fixture()
        d[0x440:0x540] = b'\x90' * 0x100
        self.assertEqual(p.find_sites(d), [])

    def test_wrong_module_name_is_ignored(self):
        d, _ = fixture()
        d[0x1420] ^= 1
        self.assertEqual(p.find_sites(d), [])

    def test_wrong_export_prefix_is_ignored(self):
        d, _ = fixture()
        d[0x1400] ^= 1
        self.assertEqual(p.find_sites(d), [])

    def test_missing_export_walk_is_ignored(self):
        d, _ = fixture()
        walk = bytes.fromhex('8b473c03c78b507883787c0003d78b722003f73b4a188b049e')
        off = d.index(walk)
        d[off:off + len(walk)] = b'\x90' * len(walk)
        self.assertEqual(p.find_sites(d), [])

    def test_disconnected_pe_fields_are_ignored(self):
        d, _ = fixture()
        off = d.index(bytes.fromhex('03d7'))  # add image base to export RVA
        d[off:off + 2] = b'\x90\x90'
        self.assertEqual(p.find_sites(d), [])

    def test_wrong_string_window_is_ignored(self):
        d, _ = fixture()
        off = d.index(bytes.fromhex('8b443a04'))
        d[off + 3] = 8
        self.assertEqual(p.find_sites(d), [])

    def test_wrong_branch_target_is_ignored(self):
        d, off = fixture()
        d[off] -= 3
        self.assertEqual(p.find_sites(d), [])

    def test_non_executable_lookalike_is_ignored(self):
        d, _ = fixture()
        struct.pack_into('<I', d, 0x178 + 36, 0x40000040)
        self.assertEqual(p.find_sites(d), [])

    def test_truncated_section_is_rejected(self):
        d, _ = fixture()
        with self.assertRaises(ValueError):
            p.find_sites(d[:-1])

    def test_backup_repeat_and_revert(self):
        d, off = fixture()
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            path = Path(folder) / 'game.dll'
            path.write_bytes(d)
            a = SimpleNamespace(src=folder, backup=os.path.join(folder, p.BACKUP_DIR),
                                yes=True, upx='unused', folder=folder)
            p.run(a, folder)
            backup = Path(a.backup) / 'game.dll'
            self.assertEqual(backup.read_bytes(), d)
            self.assertEqual(path.read_bytes()[off], 0)
            p.run(a, folder)
            self.assertEqual(backup.read_bytes(), d)
            p.revert(a)
            self.assertEqual(path.read_bytes(), d)
            self.assertFalse(Path(a.backup).exists())


ROOTS = [Path(x) for x in os.environ.get('DGVOODOO_RELEASES', '').split(os.pathsep) if x]


@unittest.skipUnless(ROOTS, 'set DGVOODOO_RELEASES for real-release regression tests')
class ReleaseTests(unittest.TestCase):
    def test_all_releases_and_mutations(self):
        for root in ROOTS:
            files, total = 0, 0
            dlls = list(root.rglob('*.dll'))
            self.assertEqual(len(dlls), 24)
            for path in dlls:
                with self.subTest(release=root.name, dll=str(path.relative_to(root))):
                    d = bytearray(path.read_bytes())
                    sites = p.find_sites(d)
                    total += len(sites)
                    files += bool(sites)
                    # Independent baseline: the old released detector's sites.
                    expected = [i + 7 for i in p.iter_find(d, bytes.fromhex('81f92cdb1b0f74'))]
                    for pool in p.iter_find(d, bytes.fromhex('ba14dab92cdb1b0f')):
                        ret = d.rfind(bytes.fromhex('20008052'), max(0, pool - 32), pool)
                        if ret >= 0 and ret % 4 == pool % 4:
                            expected.append(ret)
                    offsets = [s.offset for s in sites]
                    self.assertEqual(offsets, sorted(expected))
                    patched = bytearray(d)
                    self.assertEqual(len(p.patch(patched)), len(sites))
                    self.assertEqual(p.patch(patched), [])
                    self.assertEqual(p.already_patched(patched), bool(sites))
                    rekeyed = bytes(d)
                    for value in (0xb9da14ba, 0x0f1bdb2c, 0x546bab43, 0x9ab673cd):
                        rekeyed = rekeyed.replace(struct.pack('<I', value), struct.pack('<I', (value + 0x1234567) & 0xffffffff))
                    self.assertEqual([s.offset for s in p.find_sites(rekeyed)], offsets)
                    # Re-key the UTF-16 module initializer as well as wine_get.
                    name_keys = [0x345a, 0x92bb, 0x213f, 0x4421, 0xaab4,
                                 0x645e, 0xbcd2, 0xaf93, 0xbbdd]
                    old_keys = struct.pack('<9H', *name_keys)
                    if sites:
                        self.assertIn(old_keys, rekeyed)
                    rekeyed = rekeyed.replace(old_keys, struct.pack('<9H', *(k + 1 for k in name_keys)))
                    for value in (0x6d99cbf4, 0xbc2bdf05, 0x9bd05598, 0x50b94372):
                        lo, hi = value & 0xffff, value >> 16
                        rekeyed = rekeyed.replace(struct.pack('<I', value), struct.pack('<HH', lo - 1, hi - 1))
                    rekeyed = rekeyed.replace(bytes.fromhex('b86f440000'), bytes.fromhex('b86e440000'))
                    rekeyed = rekeyed.replace(bytes.fromhex('e88d8852'), bytes.fromhex('c88d8852'))
                    self.assertEqual([s.offset for s in p.find_sites(rekeyed)], offsets)
                    # Relocate raw sections while preserving RVAs.
                    image = p.Image(d)
                    first = min(raw for _, raw, size, _ in image.sections if size)
                    moved = d[:first] + b'\0' * 0x200 + d[first:]
                    pe = struct.unpack_from('<I', d, 0x3c)[0]
                    table = pe + 24 + struct.unpack_from('<H', d, pe + 20)[0]
                    for n, (_, raw, size, _) in enumerate(image.sections):
                        if size:
                            struct.pack_into('<I', moved, table + n * 40 + 20, raw + 0x200)
                    self.assertEqual([s.offset for s in p.find_sites(moved)], [off + 0x200 for off in offsets])
            self.assertEqual((total, files), (23, 22))


if __name__ == '__main__':
    unittest.main()
