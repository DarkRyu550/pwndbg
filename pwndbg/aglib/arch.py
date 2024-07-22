from __future__ import annotations

import pwndbg
from pwndbg.lib.arch import Arch

# We will optimize this module in the future, by having it work in the same
# way the `gdblib` version of it works, and that will come at the same
# time this module gets expanded to have the full feature set of its `gdlib`
# coutnerpart. For now, though, this should be good enough.


def __getattr__(name):
    arch = pwndbg.dbg.selected_inferior().arch()
    if name == "endian":
        return arch.endian
    elif name == "ptrsize":
        return arch.ptrsize
    else:
        return getattr(Arch(arch.name, arch.ptrsize, arch.endian), name)
