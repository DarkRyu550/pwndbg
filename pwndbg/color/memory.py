from __future__ import annotations

from typing import Any
from typing import Callable

import pwndbg
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import normal

ColorFunction = Callable[[str], str]

c = ColorConfig(
    "memory",
    [
        ColorParamSpec("stack", "yellow", "color for stack memory"),
        ColorParamSpec("heap", "blue", "color for heap memory"),
        ColorParamSpec("code", "red", "color for executable memory"),
        ColorParamSpec("data", "purple", "color for all other writable memory"),
        ColorParamSpec("rodata", "normal", "color for all read only memory"),
        ColorParamSpec("wx", "underline", "color added to all WX memory"),
        ColorParamSpec("guard", "cyan", "color added to all guard pages (no perms)"),
    ],
)


def sym_name(address: int) -> str | None:
    """
    Retrieves the name of the symbol at the given address, if it exists
    """
    return pwndbg.dbg.inferior().symbol_name_at_address(address)


def get_address_and_symbol(address: int) -> str:
    """
    Convert and colorize address 0x7ffff7fcecd0 to string `0x7ffff7fcecd0 (_dl_fini)`
    If no symbol exists for the address, return colorized address
    """
    symbol = sym_name(address)
    if symbol:
        symbol = f"{address:#x} ({symbol})"
    return get(address, symbol)


def get_address_or_symbol(address: int) -> str:
    """
    Convert and colorize address to symbol if it can be resolved, else return colorized address
    """
    return attempt_colorized_symbol(address) or get(address)


def attempt_colorized_symbol(address: int) -> str | None:
    """
    Convert address to colorized symbol (if symbol is there), else None
    """
    symbol = sym_name(address)
    if symbol:
        return get(address, symbol)
    return None


# We have to accept `Any` here, as users may pass gdb.Value objects to this
# function. This is probably more lenient than we'd really like.
#
# TODO: Remove the exception for gdb.Value case from `pwndbg.color.memory.get`.
def get(
    address: int | pwndbg.dbg_mod.Value | Any, text: str | None = None, prefix: str | None = None
) -> str:
    """
    Returns a colorized string representing the provided address.

    Arguments:
        address(int | pwndbg.dbg_mod.Value): Address to look up
        text(str | None): Optional text to use in place of the address in the return value string.
        prefix(str | None): Optional text to set at beginning in the return value string.
    """
    address = int(address)

    import pwndbg

    vmmap = pwndbg.dbg.inferior().vmmap()

    page = None
    for entry in vmmap.ranges():
        if address in entry:
            page = entry

    # The regular search failed. If we have access to `gdblib`, try the native
    # search functionality it provides.
    #
    # Currently, the `gdblib` version of the search differs from the regular
    # search in that it will explore and discover ranges, even when they are not
    # listed in the virtual memory map. So, in order to preserve the original
    # behavior of this function in all cases, this is currently necessary.
    #
    # We might want to move that discovery behavior out of `gdblib` and into the
    # agnostic library in the future. If/when that happens, we should get rid of
    # this.
    #
    # TODO: Remove this if memory range discovery behavior is no longer exclusive to `gdblib.vmmap`.
    if not page and pwndbg.dbg.is_gdblib_available():
        import pwndbg.gdblib.vmmap

        page = pwndbg.gdblib.vmmap.find(address)

    color: Callable[[str], str]

    if page is None:
        color = normal
    elif "[stack" in page.objfile:
        color = c.stack
    elif "[heap" in page.objfile:
        color = c.heap
    elif page.execute:
        color = c.code
    elif page.rw:
        color = c.data
    elif page.is_guard:
        color = c.guard
    else:
        color = c.rodata

    if page and page.wx:
        old_color = color
        color = lambda x: c.wx(old_color(x))

    if text is None and isinstance(address, int) and address > 255:
        text = hex(int(address))
    if text is None:
        text = str(int(address))

    if prefix:
        # Replace first N characters with the provided prefix
        text = prefix + text[len(prefix) :]

    return color(text)


def legend():
    return "LEGEND: " + " | ".join(
        (
            c.stack("STACK"),
            c.heap("HEAP"),
            c.code("CODE"),
            c.data("DATA"),
            # WX segments will also be marked as code, so do 2 formatters here
            c.wx(c.code("WX")),
            c.rodata("RODATA"),
        )
    )
