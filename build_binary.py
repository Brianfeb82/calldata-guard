#!/usr/bin/env python3
"""Builds a standalone, zero-dependency zipapp binary for calldata-guard."""

import shutil
import zipapp
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
DIST_DIR = REPO_ROOT / "dist"
BUILD_DIR = REPO_ROOT / "build_zipapp"


def build():
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    DIST_DIR.mkdir(exist_ok=True)
    BUILD_DIR.mkdir(parents=True)

    # Copy package into build dir
    shutil.copytree(REPO_ROOT / "src" / "calldata_guard", BUILD_DIR / "calldata_guard")

    # Clean __pycache__
    for p in BUILD_DIR.rglob("__pycache__"):
        shutil.rmtree(p)

    # Write root __main__.py to handle imports cleanly
    main_py = BUILD_DIR / "__main__.py"
    main_py.write_text(
        "import sys\n"
        "from calldata_guard.cli import main\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main())\n",
        encoding="utf-8",
    )

    target_bin = DIST_DIR / "calldata-guard"
    zipapp.create_archive(
        source=BUILD_DIR,
        target=target_bin,
        interpreter="/usr/bin/env python3",
    )
    target_bin.chmod(0o755)
    shutil.rmtree(BUILD_DIR)

    # Also build a single-file portable script calldata-guard.py
    # (can be copied anywhere and executed with python3)
    target_single = DIST_DIR / "calldata-guard.py"
    shutil.copyfile(target_bin, target_single)
    target_single.chmod(0o755)

    print(f"[OK] Standalone binary generated: {target_bin} ({target_bin.stat().st_size} bytes)")
    print(f"[OK] Portable single file:        {target_single}")


if __name__ == "__main__":
    build()
