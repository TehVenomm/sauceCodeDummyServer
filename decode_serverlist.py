#!/usr/bin/env python3
import sys
import zlib
from pathlib import Path

path = Path(sys.argv[1] if len(sys.argv) > 1 else
            "TABLE_HOST/resources/tables/serverlisttable.dat")

data = path.read_bytes()

if len(data) < 256:
    raise SystemExit("File is shorter than the 256-byte signature prefix.")

print(zlib.decompress(data[256:]).decode("utf-8"))
