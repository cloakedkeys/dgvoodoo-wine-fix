#!/usr/bin/env python3
"""
Disable dgVoodoo2's hidden Wine detection (verified on 2.87.5 and 2.87.6) so the DLLs take
the same code path under Wine as they do on Windows.

What it changes: in each copy of the obfuscated "ntdll exports wine_get*"
check, one byte, so that the check always returns "not detected".
  x86 / x64 : keyed wine_get match ; je FOUND   ->  je +0  (falls through, keeps scanning)
  ARM64     : FOUND: mov w0,#1                ->  mov w0,#0
Nothing else is modified. The VULKAN-1 (DXVK) check is left alone.

x86/x64 DLLs are UPX-packed with their markers wiped. They are restored on a
temporary copy and decompressed with the official `upx` tool (found on PATH, or
downloaded from the official release and checksum-verified). Output DLLs are
therefore unpacked (larger, same behaviour).

Usage:
  python3 patch_dgvoodoo.py                 # patch the DLLs in the folder this script is in
  python3 patch_dgvoodoo.py <folder>        # patch a dgVoodoo or game folder
  python3 patch_dgvoodoo.py --revert        # put the original DLLs back
Options: --upx /path/to/upx, --yes (don't ask on untested versions).
DLLs are patched in place; originals are first copied to <folder>/original_dlls_backup.
"""
import argparse, hashlib, os, re, shutil, struct, subprocess, sys, tempfile
from dataclasses import dataclass

try:
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64
    from capstone import CS_OP_REG, CS_OP_IMM, CS_OP_MEM
    from capstone.arm64 import ARM64_SFT_LSL
except ImportError:
    Cs = None


@dataclass(frozen=True)
class Site:
    offset: int
    patched: int = 0


class Image:
    def __init__(self, data):
        self.data = data
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        if data[:2] != b'MZ' or data[pe:pe + 4] != b'PE\0\0':
            raise ValueError('not a PE image')
        self.machine, count = struct.unpack_from('<HH', data, pe + 4)
        opt = pe + 24
        magic = struct.unpack_from('<H', data, opt)[0]
        if magic not in (0x10b, 0x20b):
            raise ValueError('unsupported PE optional header')
        self.base = struct.unpack_from('<Q' if magic == 0x20b else '<I', data,
                                       opt + (24 if magic == 0x20b else 28))[0]
        table = opt + struct.unpack_from('<H', data, pe + 20)[0]
        self.sections = []
        for n in range(count):
            o = table + n * 40
            _, rva, size, raw = struct.unpack_from('<IIII', data, o + 8)
            flags = struct.unpack_from('<I', data, o + 36)[0]
            if raw + size > len(data):
                raise ValueError('truncated PE section')
            self.sections.append((self.base + rva, raw, size, bool(flags & 0x20000000)))

    def offset(self, va, size=1):
        for start, raw, length, _ in self.sections:
            if start <= va and va + size <= start + length:
                return raw + va - start
        raise ValueError('address is not file-backed')

    def read(self, va, size):
        off = self.offset(va, size)
        return bytes(self.data[off:off + size])

def reg_id(ins, register):
    name = ins.reg_name(register)
    # Share the value of a register with its subregisters.
    aliases = {'eax': 'rax', 'ax': 'rax', 'al': 'rax',
               'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx',
               'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx',
               'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx',
               'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
               'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
               'ebp': 'rbp', 'esp': 'rsp'}
    if name in aliases:
        return aliases[name]
    if re.fullmatch(r'r\d+[dwb]', name):
        return name[:-1]
    if re.fullmatch(r'w\d+', name):
        return 'x' + name[1:]
    return name


def reg(ins, operand):
    return reg_id(ins, operand.reg)


class Flow:
    """Small straight-line evaluator, with symbolic indexed loads.

    Branches are inspected separately. Calls clobber volatile registers. Unknown
    writes discard values rather than carrying stale constants through them.
    """
    def __init__(self, image, arm=False):
        self.image, self.arm = image, arm
        self.values, self.writes, self.origins = {}, {}, {}

    def address(self, ins, op):
        m = op.mem
        base = ins.reg_name(m.base)
        if base in ('rip', 'eip'):
            return ins.address + ins.size + m.disp
        if not m.base:
            return m.disp
        value = self.values.get(reg_id(ins, m.base))
        return value + m.disp if isinstance(value, int) else None

    def value(self, ins, op):
        if op.type == CS_OP_IMM:
            return op.imm
        if op.type == CS_OP_REG:
            value = self.values.get(reg(ins, op))
            if self.arm and op.shift.value:
                return value << op.shift.value if isinstance(value, int) and op.shift.type == ARM64_SFT_LSL else None
            return value
        if op.type == CS_OP_MEM:
            address = self.address(ins, op)
            if address is not None and not op.mem.index:
                try:
                    size = op.size if not self.arm else self.width(ins.operands[0], ins)
                    return int.from_bytes(self.image.read(address, size), 'little')
                except ValueError:
                    return None
            # Keep the effective address for paired string-word loads.
            base = reg_id(ins, op.mem.base) if op.mem.base else ''
            origin, delta = self.origins.get(base, (base, 0))
            return ('load', origin, ins.reg_name(op.mem.index),
                    delta + op.mem.disp, op.mem.scale if not self.arm else 1 << op.shift.value,
                    op.size if not self.arm else self.width(ins.operands[0], ins))
        return None

    @staticmethod
    def width(op, ins):
        name = ins.reg_name(op.reg)
        return 16 if name.startswith('q') else 8 if name.startswith('x') else 4

    def step(self, ins):
        ops, name = ins.operands, ins.mnemonic
        if not ops:
            return
        dst = ops[0]
        result = None
        if name in ('call', 'bl', 'blr'):
            volatile = (['x' + str(n) for n in range(19)] if self.arm else
                        ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'])
            for r in volatile:
                self.values.pop(r, None)
                self.origins.pop(r, None)
            return
        if name in ('cmp', 'test', 'ret') or name.startswith(('j', 'b.', 'cb', 'tb')):
            return
        if name in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'adr', 'adrp') and len(ops) == 2:
            result = self.value(ins, ops[1])
        elif name == 'lea':
            if not ops[1].mem.index:
                result = self.address(ins, ops[1])
        elif name in ('ldr', 'ldar', 'ldrh'):
            if ops[1].type == CS_OP_IMM:
                try:
                    result = int.from_bytes(self.image.read(ops[1].imm, self.width(dst, ins)), 'little')
                except ValueError:
                    pass
            else:
                result = self.value(ins, ops[1])
        elif name in ('add', 'sub'):
            a, b = (self.value(ins, ops[1]), self.value(ins, ops[2])) if self.arm else (
                self.value(ins, dst), self.value(ins, ops[1]))
            if isinstance(a, int) and isinstance(b, int):
                result = a + b if name == 'add' else a - b
            elif name == 'add':
                if isinstance(a, tuple) and isinstance(b, int):
                    result = ('sum', a, b)
                elif isinstance(b, tuple) and isinstance(a, int):
                    result = ('sum', b, a)
        elif name == 'xor' and len(ops) == 2 and ops[0].reg == ops[1].reg:
            result = 0
        if dst.type == CS_OP_MEM and name in ('mov', 'movabs'):
            address = self.address(ins, dst)
            value = self.value(ins, ops[1])
            if address is not None and isinstance(value, int):
                self.store(address, value, dst.size)
        elif name in ('str', 'strh') and len(ops) == 2:
            address = self.address(ins, ops[1])
            value = self.value(ins, dst)
            if address is not None and isinstance(value, int):
                self.store(address, value, 2 if name == 'strh' else self.width(dst, ins))
        elif dst.type == CS_OP_REG:
            # Capstone's access information prevents read-only operands from
            # discarding a value (e.g. push and ARM comparisons).
            if dst.access & 2:
                origin = None
                if self.arm and name == 'add':
                    left, right = ops[1:3]
                    av, bv = self.value(ins, left), self.value(ins, right)
                    if left.type == CS_OP_REG and not left.shift.value and isinstance(bv, int) and not isinstance(av, int):
                        root, delta = self.origins.get(reg(ins, left), (reg(ins, left), 0))
                        origin = (root, delta + bv)
                    elif right.type == CS_OP_REG and not right.shift.value and isinstance(av, int) and not isinstance(bv, int):
                        root, delta = self.origins.get(reg(ins, right), (reg(ins, right), 0))
                        origin = (root, delta + av)
                self.origins.pop(reg(ins, dst), None)
                if origin:
                    self.origins[reg(ins, dst)] = origin
                self.values[reg(ins, dst)] = result
        # Also invalidate implicit outputs and secondary destinations of
        # instructions outside this evaluator (e.g. mul and ldp).
        _, writes = ins.regs_access()
        explicit = reg(ins, dst) if dst.type == CS_OP_REG and dst.access & 2 else None
        for register in writes:
            name = reg_id(ins, register)
            if name != explicit:
                self.values.pop(name, None)
                self.origins.pop(name, None)

    def store(self, address, value, size):
        for n in range(size):
            self.writes[address + n] = (value >> (8 * n)) & 255


def decode(md, image, va, length):
    for start, raw, size, code in image.sections:
        if code and start <= va < start + size:
            off = raw + va - start
            return list(md.disasm(bytes(image.data[off:off + min(length, start + size - va)]), va))
    return []


def keyed_comparisons(image, instructions, arm):
    flow, found = Flow(image, arm), []
    for n, ins in enumerate(instructions):
        if ins.mnemonic == 'cmp' and len(ins.operands) == 2:
            a, b = (flow.value(ins, op) for op in ins.operands)
            if isinstance(b, tuple) and isinstance(a, int):
                a, b = b, a
            if isinstance(a, tuple) and a[0] == 'sum' and isinstance(b, int):
                found.append((n, (b - a[2]) & 0xffffffff, a[1]))
        flow.step(ins)
    return found


def returns(image, md, address, values, expected, arm):
    flow = Flow(image, arm)
    flow.values = values.copy()
    for _ in range(32):
        block = decode(md, image, address, 16)
        if not block:
            return False
        ins = block[0]
        if ins.mnemonic == 'ret':
            value = flow.values.get('x0' if arm else 'rax')
            return isinstance(value, int) and value & 255 == expected
        if ins.mnemonic in ('jmp', 'b') and ins.operands[0].type == CS_OP_IMM:
            address = ins.operands[0].imm
            continue
        if ins.mnemonic.startswith(('j', 'b.', 'cb', 'tb')) or ins.mnemonic in ('call', 'bl', 'blr'):
            return False
        flow.step(ins)
        address += ins.size
    return False


def module_name(image, instructions, arm):
    """Recover initializer writes and the indexed UTF-16 subtraction/compare."""
    flow, loads, keys, pairs = Flow(image, arm), {}, {}, []
    for ins in instructions:
        ops = ins.operands
        if arm and ins.mnemonic == 'ldrh' and ops[1].type == CS_OP_MEM:
            address = flow.address(ins, ops[1])
            if address is not None:
                loads[reg(ins, ops[0])] = address
        if ins.mnemonic == 'sub' and len(ops) >= 2:
            if arm:
                key = loads.get(reg(ins, ops[2])) if ops[2].type == CS_OP_REG else None
                if key is not None:
                    keys[reg(ins, ops[0])] = key
            else:
                op = ops[1]
                key = (flow.address(ins, op) if op.type == CS_OP_MEM else
                       loads.get(reg(ins, op)) if op.type == CS_OP_REG else None)
                if key is not None:
                    keys[reg(ins, ops[0])] = key
        if not arm and ins.mnemonic == 'movzx' and ops[1].type == CS_OP_MEM and ops[1].size == 2:
            address = flow.address(ins, ops[1])
            if address is not None and ops[1].mem.index:
                loads[reg(ins, ops[0])] = address
        if ins.mnemonic == 'cmp':
            for a, b in ((ops[0], ops[1]), (ops[1], ops[0])):
                if a.type == CS_OP_REG and reg(ins, a) in keys:
                    stored = (flow.address(ins, b) if b.type == CS_OP_MEM else
                              loads.get(reg(ins, b)) if b.type == CS_OP_REG else None)
                    if stored is not None:
                        pairs.append((stored, keys[reg(ins, a)]))
        flow.step(ins)
    for stored, key in pairs:
        try:
            encoded = bytes(flow.writes[stored + i] for i in range(18))
            words = struct.unpack('<9H', encoded)
            keys_ = struct.unpack('<9H', image.read(key, 18))
            if ''.join(chr((s + k) & 0xffff) for s, k in zip(words, keys_)) == 'NTDLL.DLL':
                return True
        except (KeyError, ValueError):
            pass
    return False


def export_walk(instructions, arm):
    """Trace image+e_lfanew -> exports -> count and indexed name table read.

    Expressions are normalized sums of opaque inputs/loads plus a constant.
    This lets x86 memory operands and CHPE's separate address arithmetic describe
    the same PE field access, without accepting an unrelated set of offsets.
    """
    values, reads, tested = {}, [], set()

    def constant(n):
        return ((), n)

    def add(a, b):
        return (tuple(sorted(a[0] + b[0], key=repr)), a[1] + b[1])

    def unknown(name):
        return ((('input', name),), 0)

    def value(ins, op):
        if op.type == CS_OP_IMM:
            return constant(op.imm)
        if op.type == CS_OP_REG:
            result = values.get(reg(ins, op), unknown(reg(ins, op)))
            if arm and op.shift.value:
                return ((('shift', result, op.shift.type, op.shift.value),), 0)
            return result
        if op.type == CS_OP_MEM:
            address = effective(ins, op)
            result = ((('read', address),), 0)
            reads.append((address, result))
            return result
        return unknown((ins.address, 'unsupported'))

    def effective(ins, op):
        m = op.mem
        base = values.get(reg_id(ins, m.base), unknown(reg_id(ins, m.base))) if m.base else constant(0)
        if m.index:
            index = values.get(reg_id(ins, m.index), unknown(reg_id(ins, m.index)))
            base = add(base, index if not arm and m.scale == 1 else ((('index', index),), 0))
        return add(base, constant(m.disp))

    for ins in instructions:
        ops, name = ins.operands, ins.mnemonic
        if not ops:
            continue
        if name in ('cmp', 'cbz', 'cbnz'):
            tested.update(value(ins, op) for op in ops if op.type in (CS_OP_REG, CS_OP_MEM))
        result = None
        if name in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'ldr', 'ldar') and len(ops) == 2:
            result = value(ins, ops[1])
        elif name == 'lea':
            result = effective(ins, ops[1])
        elif name == 'add':
            result = add(value(ins, ops[1]), value(ins, ops[2])) if arm else add(value(ins, ops[0]), value(ins, ops[1]))
        # Discard every unknown register write, including implicit outputs.
        _, writes = ins.regs_access()
        for register in writes:
            values[reg_id(ins, register)] = unknown((ins.address, register))
        if ops[0].type == CS_OP_REG and ops[0].access & 2 and result is not None:
            values[reg(ins, ops[0])] = result
        if name in ('call', 'bl', 'blr'):
            for r in (['x' + str(n) for n in range(19)] if arm else
                      ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']):
                values[r] = unknown((ins.address, r))
        if name == 'ret':
            break
    by_address = dict(reads)
    for address, lfanew in reads:
        # e_lfanew must be a displacement of 0x3c from an image base.
        if address[1] != 0x3c:
            continue
        base = add(address, constant(-0x3c))
        header = add(base, lfanew)
        for directory, length in ((0x78, 0x7c), (0x88, 0x8c)):
            rva = by_address.get(add(header, constant(directory)))
            if rva is None or add(header, constant(length)) not in by_address:
                continue
            exports = add(base, rva)
            names = by_address.get(add(exports, constant(0x20)))
            count = by_address.get(add(exports, constant(0x18)))
            if names is None or count not in tested:
                continue
            name_table = add(base, names)
            if any(all(term in read_address[0] for term in name_table[0])
                   and read_address[1] == name_table[1] for read_address, _ in reads):
                return True
    return False


def callers(image, target, arm):
    """Locate actual relative calls or x86 callback-address materialization."""
    for start, raw, size, code in image.sections:
        if not code:
            continue
        data = bytes(image.data[raw:raw + size])
        if arm:
            for pos in range(0, size - 3, 4):
                word = int.from_bytes(data[pos:pos + 4], 'little')
                if word >> 26 == 0x25:  # BL imm26
                    delta = (word & 0x3ffffff) << 2
                    if delta & 0x8000000:
                        delta -= 0x10000000
                    if start + pos + delta == target:
                        yield start + pos
        else:
            for match in re.finditer(b'\xe8', data):
                pos = match.start()
                if pos + 5 <= size and start + pos + 5 + int.from_bytes(data[pos + 1:pos + 5], 'little', signed=True) == target:
                    yield start + pos
            if image.machine == 0x14c:
                for match in re.finditer(re.escape(target.to_bytes(4, 'little')), data):
                    pos = match.start()
                    if pos and data[pos - 1] == 0xba:  # mov edx, export callback
                        yield start + pos - 1


def context(image, md, target, arm):
    for ref in callers(image, target, arm):
        # Try bounded starts whose instruction stream reaches the reference
        # without crossing a return. ARM64 starts must also be aligned.
        for distance in range(0, 0x400, 4 if arm else 1):
            start = ref - distance
            insns = decode(md, image, start, distance + 96)
            if not any(i.address == ref for i in insns):
                continue
            if any(i.mnemonic == 'ret' and i.address < ref for i in insns):
                continue
            end = next((n + 1 for n, i in enumerate(insns) if i.mnemonic == 'ret'), len(insns))
            insns = insns[:end]
            if not module_name(image, insns, arm):
                continue
            if export_walk(insns, arm):
                return True
            # x86 keeps the export walker in a separate callback-taking helper.
            for ins in insns:
                if ins.mnemonic == 'call' and ins.operands[0].type == CS_OP_IMM:
                    if export_walk(decode(md, image, ins.operands[0].imm, 256), arm):
                        return True
    return False


def find_sites(data):
    if Cs is None:
        raise RuntimeError('Capstone is required: install it with python3 -m pip install capstone==5.0.7')
    image = Image(data)
    sites = set()
    # CHPE x86 and ARM64X carry native ARM64 code. ARM64X can also carry x64
    # code; scan each supported decoder independently and require the context.
    modes = ([(False, CS_MODE_32), (True, 0)] if image.machine == 0x14c else
             [(False, CS_MODE_64)] if image.machine == 0x8664 else
             [(True, 0), (False, CS_MODE_64)] if image.machine == 0xaa64 else
             [(True, 0)] if image.machine == 0x3a64 else [])
    for arm, mode in modes:
        md = Cs(CS_ARCH_ARM64 if arm else CS_ARCH_X86, mode)
        md.detail = True
        for va, raw, size, code in image.sections:
            if not code:
                continue
            section = bytes(data[raw:raw + size])
            if arm:
                candidates = (va + n for n in range(0, size - 3, 4)
                              if int.from_bytes(section[n:n + 4], 'little') & 0xfffffc1f == 0x7100201f)
            else:
                candidates = (va + m.start() for m in re.finditer(b'\x83[\xf8-\xff]\x08', section))
            for start in candidates:
                instructions = decode(md, image, start, 160)
                comparisons = keyed_comparisons(image, instructions, arm)
                for (a, first, load1), (b, second, load2) in zip(comparisons, comparisons[1:]):
                    if struct.pack('<II', first, second) != b'wine_get':
                        continue
                    if load1[0] != 'load' or load2[0] != 'load':
                        continue
                    # Both words must be read from the same sliding window.
                    if not (load1[1:3] == load2[1:3] and load2[3] - load1[3] == 4
                            and load1[4] == load2[4] and load1[5] == load2[5] == 4):
                        continue
                    if b + 1 >= len(instructions):
                        continue
                    branch = instructions[b + 1]
                    mismatch = instructions[a + 1]
                    if branch.mnemonic != ('b.eq' if arm else 'je') or mismatch.mnemonic != ('b.ne' if arm else 'jne'):
                        continue
                    if mismatch.operands[0].imm != branch.address + branch.size:
                        continue
                    loops = [i for i in instructions[b + 2:b + 6]
                             if i.mnemonic in ('jb', 'b.lo') and i.operands[0].imm < i.address]
                    if not loops:
                        continue
                    state = Flow(image, arm)
                    for ins in instructions[:b + 1]:
                        state.step(ins)
                    loop = loops[0]
                    if not returns(image, md, loop.address + loop.size, state.values, 0, arm):
                        continue
                    target = branch.operands[0].imm
                    expected = 1
                    if arm and image.read(target, 4) == bytes.fromhex('00008052'):
                        expected = 0  # the existing one-byte ARM64 patch
                    if target != branch.address + branch.size and not returns(image, md, target, state.values, expected, arm):
                        continue
                    # On x64 the predicate starts with a register move before
                    # cmp length,8; callers point there. Find the real entry.
                    entries = [start] if arm else [start - n for n in range(0, 17)]
                    if not any(context(image, md, entry, arm) for entry in entries):
                        continue
                    if arm:
                        success = decode(md, image, branch.operands[0].imm, 8)
                        if len(success) != 2 or success[0].mnemonic != 'mov' or success[0].op_str not in ('w0, #1', 'w0, #0') or success[1].mnemonic != 'b':
                            continue
                        sites.add(Site(image.offset(success[0].address)))
                    elif branch.size == 2:
                        sites.add(Site(image.offset(branch.address + 1)))
    return sorted(sites, key=lambda site: site.offset)


def sha(d): return hashlib.sha256(d).hexdigest()

def pe_info(d):
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    machine, nsec = struct.unpack_from('<HH', d, pe + 4)
    opt = struct.unpack_from('<H', d, pe + 20)[0]
    sh = pe + 24 + opt
    secs = []
    for i in range(nsec):
        o = sh + 40 * i
        name = d[o:o + 8]
        vsize, va, rsize, raw = struct.unpack_from('<IIII', d, o + 8)
        secs.append((o, name, vsize, rsize, raw))
    return machine, secs

def is_wiped_upx(d):
    _, secs = pe_info(d)
    return (len(secs) >= 3 and secs[0][1] == b'\0' * 8 and secs[1][1] == b'\0' * 8
            and secs[0][3] == 0 and d[0x3e0:0x3e4] == b'\0\0\0\0' and d[0x3e4] in (0x0d, 0x0e))

def nrv2e_len(src):
    """Length of the output of a UPX NRV2E (LE32) stream. Only counts, does not copy."""
    ip = bb = bc = olen = 0; last = 1
    def bit():
        nonlocal ip, bb, bc
        if bc == 0:
            bb = struct.unpack_from('<I', src, ip)[0]; ip += 4; bc = 32
        bc -= 1
        return (bb >> bc) & 1
    while True:
        while bit(): ip += 1; olen += 1
        off = 1
        while True:
            off = off * 2 + bit()
            if bit(): break
            off = (off - 1) * 2 + bit()
        if off == 2:
            off = last; n = bit()
        else:
            off = ((off - 3) * 256 + src[ip]) & 0xffffffff; ip += 1
            if off == 0xffffffff: return olen
            n = (off ^ 1) & 1; off = (off >> 1) + 1; last = off
        if n: n = 1 + bit()
        elif bit(): n = 3 + bit()
        else:
            n = 1
            while True:
                n = n * 2 + bit()
                if bit(): break
            n += 3
        olen += n + 1 + (off > 0x500)

def fix_upx_header(d, c_off):
    """Since 2.87.6 the uncompressed-size field (u_len) of the UPX header is also
    scrambled. Recover it by walking the compressed stream; the header's own
    checksum confirms the result."""
    h = 0x3e0
    if sum(d[h + 4:h + 31]) % 251 == d[h + 31]: return
    method, c_len = d[h + 6], struct.unpack_from('<I', d, h + 20)[0]
    if method != 8:
        raise RuntimeError(f'UPX header damaged and compression method {method} is not supported')
    struct.pack_into('<I', d, h + 16, nrv2e_len(bytes(d[c_off:c_off + c_len])))
    if sum(d[h + 4:h + 31]) % 251 != d[h + 31]:
        raise RuntimeError('UPX header damaged and could not be repaired')

def unpack(d, upx):
    d = bytearray(d)
    _, secs = pe_info(d)
    d[secs[0][0]:secs[0][0] + 8] = b'UPX0\0\0\0\0'
    d[secs[1][0]:secs[1][0] + 8] = b'UPX1\0\0\0\0'
    d[0x3e0:0x3e4] = b'UPX!'
    fix_upx_header(d, secs[1][4])
    with tempfile.TemporaryDirectory() as t:
        src, dst = os.path.join(t, 'in.dll'), os.path.join(t, 'out.dll')
        open(src, 'wb').write(d)
        r = subprocess.run([upx, '-d', '-q', '-o', dst, src], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError('upx failed: ' + (r.stderr or r.stdout).strip())
        return bytearray(open(dst, 'rb').read())

def patch(d, sites=None):
    """Return list of (offset, old, new) applied."""
    done = []
    for site in find_sites(d) if sites is None else sites:
        if d[site.offset] != site.patched:
            done.append((site.offset, d[site.offset], site.patched))
            d[site.offset] = site.patched
    return done

TESTED_VERSIONS = {'2.8.7.5', '2.8.7.6'}   # dgVoodooCpl.exe FileVersion of releases this was verified on

def dgvoodoo_version(src):
    """FileVersion of dgVoodooCpl.exe (from its VS_FIXEDFILEINFO), or None."""
    for rel in ('dgVoodooCpl.exe', os.path.join('Cpl', 'x64', 'dgVoodooCpl.exe'),
                os.path.join('Cpl', 'arm64', 'dgVoodooCpl.exe')):
        p = os.path.join(src, rel)
        if not os.path.exists(p): continue
        d = open(p, 'rb').read()
        i = d.find(b'\xbd\x04\xef\xfe')            # VS_FIXEDFILEINFO signature
        if i < 0: continue
        ms, ls = struct.unpack_from('<II', d, i + 8)
        return f'{ms >> 16}.{ms & 0xffff}.{ls >> 16}.{ls & 0xffff}'
    return None

def confirm_version(src, assume_yes):
    v = dgvoodoo_version(src)
    if v in TESTED_VERSIONS:
        print(f'dgVoodoo version {v} (tested).\n')
        return True
    print('WARNING: ' + (f'dgVoodoo version {v} has not been tested with this patcher.' if v
                         else 'Could not determine the dgVoodoo version (dgVoodooCpl.exe not found).'))
    print('The patch decodes keyed strings and validates the ntdll export walk. Other versions may\n'
          'find nothing, or (unlikely) change the wrong byte. Your originals are not modified\n'
          'either way, but test the patched DLLs before relying on them.')
    if assume_yes:
        print('Continuing because --yes was given.\n')
        return True
    try:
        ans = input('Continue anyway? [y/N] ')
    except EOFError:
        ans = ''
    print()
    return ans.strip().lower() in ('y', 'yes')

UPX_VER = '4.2.4'
UPX_DL = {  # official upx/upx GitHub release, pinned by SHA-256
    'win32': ('upx-4.2.4-win64.zip', 'upx.exe',
              '22e9ef20e4c72aad85e32c71cbc9c086436c179456382aa75c0c24868456a671'),
    'linux': ('upx-4.2.4-amd64_linux.tar.xz', 'upx',
              '75cab4e57ab72fb4585ee45ff36388d280c7afd72aa03e8d4b9c3cbddb474193'),
}

def find_upx(here):
    exe = shutil.which('upx')
    if exe: return exe
    plat = 'win32' if sys.platform.startswith('win') else 'linux' if sys.platform.startswith('linux') else None
    if not plat:
        sys.exit('Please install UPX (https://upx.github.io) and run again.')
    name, binname, want = UPX_DL[plat]
    cache = os.path.join(here, 'upx-' + UPX_VER)
    path = os.path.join(cache, binname)
    if os.path.exists(path): return path
    import urllib.request, zipfile, tarfile, io
    url = f'https://github.com/upx/upx/releases/download/v{UPX_VER}/{name}'
    print(f'Downloading UPX {UPX_VER} from {url} ...')
    data = urllib.request.urlopen(url, timeout=60).read()
    if sha(data) != want:
        sys.exit('UPX download failed its checksum; not using it.')
    os.makedirs(cache, exist_ok=True)
    if name.endswith('.zip'):
        member = zipfile.ZipFile(io.BytesIO(data)).read(f'{name[:-4]}/{binname}')
    else:
        member = tarfile.open(fileobj=io.BytesIO(data)).extractfile(f'{name[:-7]}/{binname}').read()
    open(path, 'wb').write(member)
    os.chmod(path, 0o755)
    return path

BACKUP_DIR = 'original_dlls_backup'

def already_patched(d):
    """True if every copy of the check in d is in its patched form."""
    sites = find_sites(d)
    return bool(sites) and all(d[site.offset] == site.patched for site in sites)

def iter_find(d, pat):
    i = d.find(pat)
    while i >= 0:
        yield i; i = d.find(pat, i + 1)

def replace_file(path, data):
    tmp = path + '.tmp'
    open(tmp, 'wb').write(data)
    os.replace(tmp, path)

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument('folder', nargs='?', help='dgVoodoo or game folder (default: folder this script is in)')
    ap.add_argument('--revert', action='store_true', help=f'put the original DLLs back from {BACKUP_DIR}/')
    ap.add_argument('--upx', help='path to upx (default: find or download it)')
    ap.add_argument('--yes', action='store_true', help='do not ask for confirmation on untested versions')
    a = ap.parse_args()
    interactive = a.folder is None
    a.src = os.path.abspath(a.folder or here)
    a.backup = os.path.join(a.src, BACKUP_DIR)
    try:
        revert(a) if a.revert else run(a, here)
    finally:
        if interactive and sys.platform.startswith('win'):
            input('\nPress Enter to close...')

def revert(a):
    if not os.path.isdir(a.backup):
        print(f'Nothing to revert: no {BACKUP_DIR} folder in {a.src}'); return
    n = 0; failed = 0
    for root, _, files in os.walk(a.backup):
        for f in files:
            b = os.path.join(root, f); rel = os.path.relpath(b, a.backup)
            try:
                replace_file(os.path.join(a.src, rel), open(b, 'rb').read())
                print(f'restored  {rel}'); n += 1
            except OSError as e:
                print(f'ERROR     {rel}: {e}'); failed += 1
    if failed:
        print(f'\n{n} restored, {failed} failed (is a game still running?). Backup kept in {a.backup}')
    else:
        shutil.rmtree(a.backup)
        print(f'\n{n} original DLL(s) restored. Backup folder removed.')

def run(a, here):
    if not confirm_version(a.src, a.yes):
        print('Cancelled. Nothing was changed.')
        return
    if Cs is None:
        sys.exit('Capstone is required: install it with python3 -m pip install capstone==5.0.7')
    a.upx = a.upx or find_upx(here)
    total = 0; problems = 0; done_before = 0
    for root, dirs, files in os.walk(a.src):
        dirs[:] = [x for x in dirs if os.path.join(root, x) != a.backup and not x.startswith('upx-')]
        for f in sorted(files):
            if not f.lower().endswith('.dll'): continue
            p = os.path.join(root, f); rel = os.path.relpath(p, a.src)
            orig = open(p, 'rb').read()
            d = bytearray(orig)
            packed = is_wiped_upx(d)
            if packed:  # code is compressed; unpack before searching
                try: d = unpack(d, a.upx)
                except Exception as e:
                    print(f'ERROR  {rel}: {e}'); problems += 1; continue
            try:
                sites = find_sites(d)
            except (ValueError, struct.error) as e:
                print(f'WARN   {rel}: cannot analyze PE image: {e}'); problems += 1; continue
            if not sites:
                print(f'skip   {rel}: no recognized Wine check'); continue
            if not packed and all(d[site.offset] == site.patched for site in sites):
                print(f'ok     {rel}: already patched'); done_before += 1; continue
            changes = patch(d, sites)
            if not changes:
                print(f'WARN   {rel}: Wine check found but no known patch site'); problems += 1; continue
            try:
                bak = os.path.join(a.backup, rel)
                os.makedirs(os.path.dirname(bak), exist_ok=True)
                open(bak, 'wb').write(orig)              # back up the unpatched original first
                replace_file(p, d)
            except OSError as e:
                print(f'ERROR  {rel}: {e} (is a game still running?)'); problems += 1; continue
            total += len(changes)
            desc = ', '.join(f'0x{o:x}: {old:02x}->{new:02x}' for o, old, new in changes)
            print(f'patch  {rel}{" (unpacked)" if packed else ""}: {desc}')
    print(f'\n{total} patch site(s) applied. Already patched: {done_before}. Problems: {problems}.')
    if total:
        print(f'Originals backed up in: {a.backup}')
        where = f' "{a.folder}"' if a.folder else ''
        print(f'To undo: python3 patch_dgvoodoo.py{where} --revert')
    elif not problems and not done_before:
        print('No dgVoodoo DLLs with the Wine check were found here.')

if __name__ == '__main__':
    main()
