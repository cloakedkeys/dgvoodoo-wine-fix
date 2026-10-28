# dgVoodoo Wine Fix

Newer dgVoodoo2 versions secretly check for Wine and, if found, corrupt graphics pointers so games crash ([WineHQ bug 58731](https://bugs.winehq.org/show_bug.cgi?id=58731)). This script turns that check off. Your original files are backed up first, and one command puts them back.

Tested with **dgVoodoo 2.87.5 and 2.87.6**. On any other version it warns you and asks whether to continue. It may still work on other versions, but YMMV.

## How to use

1. **Get Python 3 and Capstone.** Install the instruction decoder once:

   ```sh
   python3 -m pip install capstone==5.0.7
   ```
2. **Get dgVoodoo 2.87.6** from the [official releases page](https://github.com/dege-diosg/dgVoodoo2/releases/tag/2.87.6) (`dgVoodoo2_87_6.zip`) and unzip it.
3. **Download `patch_dgvoodoo.py` into the unzipped dgVoodoo folder.** Open a terminal in that folder and run:

   ```sh
   curl -LO https://raw.githubusercontent.com/cloakedkeys/dgvoodoo-wine-fix/main/patch_dgvoodoo.py
   ```

   Or right-click [this link](https://raw.githubusercontent.com/cloakedkeys/dgvoodoo-wine-fix/main/patch_dgvoodoo.py) and choose "Save link as…". Don't save the script's GitHub page (the one with the code view and buttons): that saves a web page, not the script.
4. **Run it.**
   - Linux: open a terminal in that folder and type `python3 patch_dgvoodoo.py`.

   The first time it runs, it automatically downloads [UPX](https://github.com/upx/upx), a free tool it needs to unpack the DLLs. This needs an internet connection; you don't have to install anything yourself.
5. That's it. The DLLs are fixed in place, and your originals are saved in a new folder called **`original_dlls_backup`**. Copy the fixed DLLs into your game as usual. For example, `MS/x86/D3D8.dll`.

If it says `23 patch site(s) applied. Problems: 0.`, it worked.

**Already copied dgVoodoo into a game?** Fix it there directly: `python3 patch_dgvoodoo.py "/path/to/game"`. It will warn that it can't tell the version; type `y` to continue.

**`SyntaxError: invalid character '·' (U+00B7)`?** You saved the GitHub web page instead of the script. Download it again with the `curl` command in step 3.

**Something broke?** Undo everything with `python3 patch_dgvoodoo.py --revert` (add the game folder path if you used one).

## What it changes

It changes one byte in each copy of the hidden Wine check (23 copies across 22 DLLs), so the check always answers "not Wine". Nothing else is touched.

The x86/x64 DLLs are compressed with UPX, so the script unpacks them first. This makes the patched files bigger, but they behave the same. If UPX isn't installed, the script downloads the official UPX 4.2.4 release and checks its checksum first.

The detector disassembles executable PE sections and follows references to the
Wine predicate. It reconstructs the scrambled `NTDLL.DLL` initializer, adds the
UTF-16 keys to recover the name, validates the PE export-name walk, and decodes
the two keyed comparisons to `wine_get`. It checks the sliding-window reads,
branches, and return paths before choosing a patch byte. All analysis is static;
the DLLs are never loaded or executed.

Keys, comparison constants, image bases, file offsets, and the distance between
the export walker and predicate are not fixed. x86, x64, ARM64, CHPE x86, and both
ARM64X copies are covered. This is a bounded decoder for the observed algorithm,
not a general decompiler: a different algorithm, instruction form, or compiler
layout can still be unrecognized. Unrecognized forms are left untouched; keep
the version warning and test an unfamiliar release before using it.

## Tests

Run `python3 -m unittest discover -s tests -v`. To include real-release regression
tests, set `DGVOODOO_RELEASES` to unpacked release directories separated by your
platform's path separator (`:` on Linux, `;` on Windows). Each directory should
contain the full 24-DLL release tree after UPX decompression. These optional tests
also re-key the Wine comparisons and move the sections in the file. No proprietary
DLLs are included in this repository.
