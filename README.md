# dgVoodoo Wine Fix

Newer dgVoodoo2 versions secretly check for Wine and, if found, corrupt graphics pointers so games crash ([WineHQ bug 58731](https://bugs.winehq.org/show_bug.cgi?id=58731)). This script turns that check off. Your original files are backed up first, and one command puts them back.

Tested with **dgVoodoo 2.87.5**. On any other version it warns you and asks whether to continue. It may still work on other versions, but YMMV.

## How to use

1. **Get Python 3.**
   - Linux: you already have it.
2. **Get dgVoodoo 2.87.5** from the [official releases page](https://github.com/dege-diosg/dgVoodoo2/releases/tag/v2.87.5) (`dgVoodoo2_87_5.zip`) and unzip it.
3. **Download [`patch_dgvoodoo.py`](https://raw.githubusercontent.com/cloakedkeys/dgvoodoo-wine-fix/main/patch_dgvoodoo.py)** (right-click the link, then "Save link as…") and save it into the unzipped dgVoodoo folder.
4. **Run it.**
   - Linux: open a terminal in that folder and type `python3 patch_dgvoodoo.py`.

   The first time it runs, it automatically downloads [UPX](https://github.com/upx/upx), a free tool it needs to unpack the DLLs. This needs an internet connection; you don't have to install anything yourself.
5. That's it. The DLLs are fixed in place, and your originals are saved in a new folder called **`original_dlls_backup`**. Copy the fixed DLLs into your game as usual. For example, `MS/x86/D3D8.dll`.

If it says `23 patch site(s) applied. Problems: 0.`, it worked.

**Already copied dgVoodoo into a game?** Fix it there directly: `python3 patch_dgvoodoo.py "/path/to/game"`. It will warn that it can't tell the version; type `y` to continue.

**Something broke?** Undo everything with `python3 patch_dgvoodoo.py --revert` (add the game folder path if you used one).

## What it changes

It changes one byte in each copy of the hidden Wine check (23 copies across 22 DLLs), so the check always answers "not Wine". Nothing else is touched.

The x86/x64 DLLs are compressed with UPX, so the script unpacks them first. This makes the patched files bigger, but they behave the same. If UPX isn't installed, the script downloads the official UPX 4.2.4 release and checks its checksum first.
