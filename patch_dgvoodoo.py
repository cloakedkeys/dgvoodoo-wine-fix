#!/usr/bin/env python3
"""
Disable dgVoodoo2's hidden Wine detection (verified on 2.87.5 and 2.87.6) so the DLLs take
the same code path under Wine as they do on Windows.

What it changes: in each copy of the obfuscated "ntdll exports wine_get*"
check, one byte, so that the check always returns "not detected".
  x86 / x64 : cmp ecx,0x0f1bdb2c ; je FOUND   ->  je +0  (falls through, keeps scanning)
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
import argparse, hashlib, os, shutil, struct, subprocess, sys, tempfile

WINE_CMP2 = (0x0f1bdb2c).to_bytes(4, 'little')
X86_SIG = b'\x81\xf9' + WINE_CMP2 + b'\x74'           # cmp ecx, imm32 ; je rel8
A64_POOL = (0xb9da14ba).to_bytes(4, 'little') + WINE_CMP2
A64_RET1 = bytes.fromhex('20008052')                   # mov w0, #1
A64_RET0 = bytes.fromhex('00008052')                   # mov w0, #0

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

def patch(d):
    """Return list of (offset, old, new) applied."""
    done = []
    # x86 / x64 form
    i = d.find(X86_SIG)
    while i >= 0:
        o = i + len(X86_SIG)                 # rel8 displacement byte
        if d[o] != 0:
            done.append((o, d[o], 0)); d[o] = 0
        i = d.find(X86_SIG, i + 1)
    # ARM64 form: 'mov w0,#1' shortly before the literal pool holding both constants
    i = d.find(A64_POOL)
    while i >= 0:
        j = d.rfind(A64_RET1, max(0, i - 0x20), i)
        if j >= 0 and j % 4 == i % 4:
            done.append((j, d[j], 0)); d[j:j + 4] = A64_RET0
        i = d.find(A64_POOL, i + 1)
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
    print('The patch looks for the exact code pattern found in 2.87.5 and 2.87.6. On other versions it may\n'
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
    x86 = [i for i in iter_find(d, X86_SIG)]
    a64 = [i for i in iter_find(d, A64_POOL)]
    if not x86 and not a64: return False
    return (all(d[i + len(X86_SIG)] == 0 for i in x86) and
            all(d.rfind(A64_RET1, max(0, i - 0x20), i) < 0 for i in a64))

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
            if WINE_CMP2 not in d:
                print(f'skip   {rel}: no Wine check present'); continue
            if not packed and already_patched(d):
                print(f'ok     {rel}: already patched'); done_before += 1; continue
            changes = patch(d)
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
