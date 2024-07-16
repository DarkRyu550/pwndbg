"""
Code that sets up hooks for LLDB events.
"""

from __future__ import annotations

import pwndbg
import pwndbg.aglib.typeinfo
from pwndbg.dbg import EventType
from pwndbg.dbg.lldb import LLDB


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.STOP)
def update_typeinfo() -> None:
    pwndbg.aglib.typeinfo.update()


import pwndbg.lib.cache

pwndbg.lib.cache.connect_clear_caching_events(
    {
        "exit": (pwndbg.dbg.event_handler(EventType.EXIT),),
        "objfile": (pwndbg.dbg.event_handler(EventType.NEW_MODULE),),
        "start": (pwndbg.dbg.event_handler(EventType.START),),
        "prompt": (),
        "forever": (),
    },
)

# As we don't have support for MEMORY_CHANGED, REGISTER_CHANGED, or NEW_THREAD
# yet, we disable these cache types, as we can't provide the same behavior for
# them as GDB can.
#
# TODO: Implement missing event types and re-enable the cache types that depend on them.
pwndbg.lib.cache.IS_CACHING_DISABLED_FOR["stop"] = True
pwndbg.lib.cache.IS_CACHING_DISABLED_FOR["thread"] = True
pwndbg.lib.cache.IS_CACHING_DISABLED_FOR["cont"] = True


def prompt_hook():
    # Clear the prompt cache manually.
    pwndbg.lib.cache.clear_cache("prompt")

    # We'll eventually want to call `context` here.


# Install the prompt hook.
assert isinstance(pwndbg.dbg, LLDB)
dbg: LLDB = pwndbg.dbg

dbg.prompt_hook = prompt_hook
