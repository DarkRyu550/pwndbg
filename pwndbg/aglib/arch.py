from __future__ import annotations

import pwndbg

def __getattr__(name):
    if name == "endian":
        frame = pwndbg.dbg.session().selected_frame()
        if frame:
            return frame.module().arch().endian()
        else:
            return pwndbg.dbg.inferior().arch().endian()
    elif name == "ptrsize":
        frame = pwndbg.dbg.session().selected_frame()
        if frame:
            return frame.module().arch().ptrsize()
        else:
            return pwndbg.dbg.inferior().arch().ptrsize()
