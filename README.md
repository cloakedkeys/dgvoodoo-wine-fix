# dgVoodoo Wine Fix

Newer dgVoodoo2 versions secretly check for Wine and, if found, corrupt graphics pointers so games crash ([WineHQ bug 58731](https://bugs.winehq.org/show_bug.cgi?id=58731)). This script turns that check off. Your original files are not changed.

Tested with **dgVoodoo 2.87.5**. On any other version it warns you and asks whether to continue. It may still work on other versions, but test the result.

## How to use

1. **Get Python 3.**
   - Windows: install it from [python.org](https://www.python.org/downloads/). During setup, tick **"Add python.exe to PATH"**.
   - Linux: you already have it.
2. **Get dgVoodoo 2.87.5** from the [official releases page](https://github.com/dege-diosg/dgVoodoo2/releases/tag/v2.87.5) (`dgVoodoo2_87_5.zip`) and unzip it.
3. **Download [`patch_dgvoodoo.py`](https://raw.githubusercontent.com/cloakedkeys/dgvoodoo-wine-fix/main/patch_dgvoodoo.py)** (right-click the link, then "Save link as…") and save it into the unzipped dgVoodoo folder.
4. **Run it.**
   - Windows: double-click `patch_dgvoodoo.py`.
   - Linux: open a terminal in that folder and type `python3 patch_dgvoodoo.py`.
5. A new folder called **`patched`** appears. Use the DLLs from it instead of the normal ones. For example, copy `patched/MS/x86/D3D8.dll` into your game's folder.

If it says `23 patch site(s) applied. Problems: 0.`, it worked.

## What it changes

It changes one byte in each copy of the hidden Wine check (23 copies across 22 DLLs), so the check always answers "not Wine". Nothing else is touched.

The x86/x64 DLLs are compressed with UPX, so the script unpacks them first. This makes the patched files bigger, but they behave the same. If UPX isn't installed, the script downloads the official UPX 4.2.4 release and checks its checksum first.
