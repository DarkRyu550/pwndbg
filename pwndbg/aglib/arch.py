from __future__ import annotations

import pwndbg


def __getattr__(name):
    if name == "endian":
        return pwndbg.dbg.inferior().arch().endian()
    elif name == "ptrsize":
        return pwndbg.dbg.inferior().arch().ptrsize()
