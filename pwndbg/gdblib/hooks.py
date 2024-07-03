from __future__ import annotations

import gdb

import pwndbg.aglib.typeinfo
import pwndbg.gdblib.abi
import pwndbg.gdblib.events
import pwndbg.gdblib.file
import pwndbg.gdblib.memory
import pwndbg.gdblib.next
import pwndbg.gdblib.tls
import pwndbg.gdblib.typeinfo
from pwndbg.gdblib import arch_mod

# TODO: Combine these `update_*` hook callbacks into one method


@pwndbg.gdblib.events.new_objfile
@pwndbg.gdblib.events.start
@pwndbg.gdblib.events.stop
def update_typeinfo() -> None:
    # Initialize the typing information in aglib.
    # Workaround for Rust stuff, see https://github.com/pwndbg/pwndbg/issues/855
    lang = gdb.execute("show language", to_string=True)
    if "rust" not in lang:
        restore_lang = None
    else:
        gdb.execute("set language c")
        if '"auto;' in lang:
            restore_lang = "auto"
        else:
            restore_lang = "rust"

    pwndbg.gdblib.typeinfo.update()
    pwndbg.aglib.typeinfo.update()

    # Rust workaround part 2
    if restore_lang:
        gdb.execute(f"set language {restore_lang}")



@pwndbg.gdblib.events.start
@pwndbg.gdblib.events.stop
@pwndbg.gdblib.events.new_objfile
def update_arch() -> None:
    arch_mod.update()


@pwndbg.gdblib.events.new_objfile
def reset_config() -> None:
    pwndbg.gdblib.kernel._kconfig = None


@pwndbg.gdblib.events.start
def on_start() -> None:
    pwndbg.gdblib.abi.update()
    pwndbg.gdblib.memory.update_min_addr()


@pwndbg.gdblib.events.exit
def on_exit() -> None:
    pwndbg.gdblib.file.reset_remote_files()
    pwndbg.gdblib.next.clear_temp_breaks()


@pwndbg.gdblib.events.stop
def on_stop() -> None:
    pwndbg.gdblib.strings.update_length()


import pwndbg.lib.cache

pwndbg.lib.cache.connect_clear_caching_events(
    {
        # Any cache that should be cleared when the program is stopped should also be cleared
        # if the user does an operation to modify memory or registers while the program is stopped.
        # We don't do this for the other events, because they hopefully don't change memory or
        # registers
        "stop": (
            pwndbg.gdblib.events.stop,
            pwndbg.gdblib.events.mem_changed,
            pwndbg.gdblib.events.reg_changed,
        ),
        "exit": (pwndbg.gdblib.events.exit,),
        "objfile": (pwndbg.gdblib.events.new_objfile,),
        "start": (pwndbg.gdblib.events.start,),
        "cont": (
            pwndbg.gdblib.events.cont,
            pwndbg.gdblib.events.mem_changed,
            pwndbg.gdblib.events.reg_changed,
        ),
        "thread": (pwndbg.gdblib.events.thread,),
        "prompt": (pwndbg.gdblib.events.before_prompt,),
        "forever": (),
    },
    priority=pwndbg.gdblib.events.HandlerPriority.CACHE_CLEAR,
)


def init() -> None:
    """Calls all GDB hook functions that need to be called when GDB/pwndbg
    itself is loaded, as opposed to when an actual hook event occurs
    """
    update_arch()
    update_typeinfo()
    pwndbg.gdblib.abi.update()


init()
