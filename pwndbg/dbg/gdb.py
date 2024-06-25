from __future__ import annotations

import signal
from typing import Any
from typing import List
from typing import Tuple

import gdb
from typing_extensions import Callable
from typing_extensions import override

import pwndbg
import pwndbg.commands
import pwndbg.gdblib
from pwndbg.commands import load_commands
from pwndbg.gdblib import gdb_version
from pwndbg.gdblib import load_gdblib


class GDBFrame(pwndbg.dbg_mod.Frame):
    def __init__(self, inner: gdb.Frame):
        self.inner = inner

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        selected = gdb.selected_frame()
        restore = False
        if selected != self.inner:
            self.inner.select()
            restore = True

        try:
            value = gdb.parse_and_eval(expression, global_context=False)
        except TypeError:
            # Some earlier versions of GDB don't support the global_context keyword.
            value = gdb.parse_and_eval(expression)
        finally:
            if restore:
                selected.select()

        return GDBValue(value)


class GDBThread(pwndbg.dbg_mod.Thread):
    def __init__(self, inner: gdb.Thread):
        self.inner = inner

    @override
    def bottom_frame(self) -> pwndbg.dbg_mod.Frame:
        selected = gdb.selected_thread()
        restore = False
        if selected != self.inner:
            self.inner.switch()
            restore = True

        value = gdb.newest_frame()
        if restore:
            selected.switch()
        return GDBFrame(value)


class GDBProcess(pwndbg.dbg_mod.Process):
    def __init__(self, inner: gdb.Inferior):
        self.inner = inner

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        try:
            return GDBValue(gdb.parse_and_eval(expression, global_context=True))
        except TypeError:
            # Some earlier versions of GDB don't support the global_context keyword.
            return GDBValue(gdb.parse_and_eval(expression))


class GDBSession(pwndbg.dbg_mod.Session):
    @override
    def history(self) -> List[str]:
        lines = gdb.execute("show commands", from_tty=False, to_string=True)
        return lines.splitlines()

    @override
    def lex_args(self, command_line: str) -> List[str]:
        return gdb.string_to_argv(command_line)

    @override
    def selected_thread(self) -> pwndbg.dbg_mod.Thread:
        thread = gdb.selected_thread()
        if thread:
            return GDBThread(thread)

    @override
    def selected_frame(self) -> pwndbg.dbg_mod.Frame:
        try:
            frame = gdb.selected_frame()
            if frame:
                return GDBFrame(frame)
        except gdb.error:
            pass
        return None


class GDBCommand(gdb.Command):
    def __init__(
        self,
        debugger: GDB,
        name: str,
        handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None],
    ):
        self.debugger = debugger
        self.handler = handler
        super().__init__(name, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)

    def invoke(self, args: str, from_tty: bool) -> None:
        self.handler(self.debugger, args, from_tty)


class GDBCommandHandle(pwndbg.dbg_mod.CommandHandle):
    def __init__(self, command: gdb.Command):
        self.command = command

    def remove(self) -> None:
        # GDB doesn't support command removal?
        pass


class GDBType(pwndbg.dbg_mod.Type):
    CODE_MAPPING = {
        gdb.TYPE_CODE_INT: pwndbg.dbg_mod.TypeCode.INT,
        gdb.TYPE_CODE_UNION: pwndbg.dbg_mod.TypeCode.UNION,
        gdb.TYPE_CODE_STRUCT: pwndbg.dbg_mod.TypeCode.STRUCT,
        gdb.TYPE_CODE_ENUM: pwndbg.dbg_mod.TypeCode.ENUM,
        gdb.TYPE_CODE_TYPEDEF: pwndbg.dbg_mod.TypeCode.TYPEDEF,
        gdb.TYPE_CODE_PTR: pwndbg.dbg_mod.TypeCode.POINTER,
        gdb.TYPE_CODE_ARRAY: pwndbg.dbg_mod.TypeCode.ARRAY,
    }

    def __init__(self, inner: gdb.Type):
        self.inner = inner

    @property
    @override
    def alignof(self) -> int:
        return self.inner.alignof

    @property
    @override
    def code(self) -> pwndbg.dbg_mod.TypeCode:
        assert self.inner.code in GDBType.CODE_MAPPING, "missing mapping for type code"
        return GDBType.CODE_MAPPING[self.inner.code]

    @override
    def fields(self) -> List[pwndbg.dbg_mod.TypeField] | None:
        return [
            pwndbg.dbg_mod.TypeField(
                field.bitpos,
                field.name,
                GDBType(field.type),
                field.parent_type,
                field.enumval,
                field.artificial,
                field.is_base_class,
                field.bitsize,
            )
            for field in self.inner.fields()
        ]

    @override
    def array(self, count: int) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.array(count))

    @override
    def pointer(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.pointer())

    @override
    def strip_typedefs(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.strip_typedefs())

    @override
    def target(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.target())


class GDBValue(pwndbg.dbg_mod.Value):
    def __init__(self, inner: gdb.Value):
        self.inner = inner

    @property
    @override
    def address(self) -> pwndbg.dbg_mod.Value | None:
        return GDBValue(self.inner.address)

    @property
    @override
    def is_optimized_out(self) -> bool:
        return self.inner.is_optimized_out

    @property
    @override
    def type(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.type)

    @override
    def dereference(self) -> pwndbg.dbg_mod.Value:
        return GDBValue(self.inner.dereference())

    @override
    def string(self) -> str:
        return self.inner.string()

    @override
    def fetch_lazy(self) -> None:
        self.inner.fetch_lazy()

    @override
    def __int__(self) -> int:
        return int(self.inner)

    @override
    def cast(self, type: pwndbg.dbg_mod.Type | Any) -> pwndbg.dbg_mod.Value:
        # We let the consumers of this function just pass it a `gdb.Type`.
        # This keeps us from breaking functionality under GDB until we have
        # better support for type lookup under LLDB and start porting the
        # commands that need this to the new API.
        #
        # FIXME: Remove sloppy `gdb.Type` exception in `GDBValue.cast()`
        if isinstance(type, gdb.Type):
            return GDBValue(self.inner.cast(type))

        assert isinstance(type, GDBType)
        t: GDBType = type

        return GDBValue(self.inner.cast(t.inner))


class GDB(pwndbg.dbg_mod.Debugger):
    @override
    def setup(self):
        load_gdblib()
        load_commands()

        from pwndbg.gdblib import prompt

        prompt.set_prompt()

        pre_commands = f"""
        set confirm off
        set verbose off
        set pagination off
        set height 0
        set history save on
        set follow-fork-mode child
        set backtrace past-main on
        set step-mode on
        set print pretty on
        set width {pwndbg.ui.get_window_size()[1]}
        handle SIGALRM nostop print nopass
        handle SIGBUS  stop   print nopass
        handle SIGPIPE nostop print nopass
        handle SIGSEGV stop   print nopass
        """.strip()

        # See https://github.com/pwndbg/pwndbg/issues/808
        if gdb_version[0] <= 9:
            pre_commands += "\nset remote search-memory-packet off"

        for line in pre_commands.strip().splitlines():
            gdb.execute(line)

        # This may throw an exception, see pwndbg/pwndbg#27
        try:
            gdb.execute("set disassembly-flavor intel")
        except gdb.error:
            pass

        # handle resize event to align width and completion
        signal.signal(
            signal.SIGWINCH,
            lambda signum, frame: gdb.execute("set width %i" % pwndbg.ui.get_window_size()[1]),
        )

        # Reading Comment file
        from pwndbg.commands import comments

        comments.init()

        from pwndbg.gdblib import config_mod

        config_mod.init_params()

        prompt.show_hint()

    @override
    def add_command(
        self, name: str, handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None]
    ) -> pwndbg.dbg_mod.CommandHandle:
        command = GDBCommand(self, name, handler)
        return GDBCommandHandle(command)

    @override
    def session(self) -> pwndbg.dbg_mod.Session | None:
        # FIXME: Creating a new object every time is unnecessary.
        return GDBSession()

    @override
    def inferior(self) -> pwndbg.dbg_mod.Process | None:
        return GDBProcess(gdb.selected_inferior())

    @override
    def addrsz(self, address: Any) -> str:
        address = int(address) & pwndbg.gdblib.arch.ptrmask
        return f"%#{2 * pwndbg.gdblib.arch.ptrsize}x" % address

    @override
    def get_cmd_window_size(self) -> Tuple[int, int]:
        """Get the size of the command window in TUI mode which could be different than the terminal window width \
        with horizontal split "tui new-layout hsrc { -horizontal src 1 cmd 1 } 1".

        Possible output of "info win" in TUI mode:
        (gdb) info win
        Name       Lines Columns Focus
        src           77     104 (has focus)
        cmd           77     105

        Output of "info win" in non-TUI mode:
        (gdb) info win
        The TUI is not active."""
        try:
            info_out = gdb.execute("info win", to_string=True).split()
        except gdb.error:
            # Return None if the command is not compiled into GDB
            # (gdb.error: Undefined info command: "win".  Try "help info")
            return None, None
        if "cmd" not in info_out:
            # if TUI is not enabled, info win will output "The TUI is not active."
            return None, None
        # parse cmd window size from the output of "info win"
        cmd_win_index = info_out.index("cmd")
        if len(info_out) <= cmd_win_index + 2:
            return None, None
        elif (
            not info_out[cmd_win_index + 1].isdigit() and not info_out[cmd_win_index + 2].isdigit()
        ):
            return None, None
        else:
            return int(info_out[cmd_win_index + 1]), int(info_out[cmd_win_index + 2])

    @override
    def set_python_diagnostics(self, enabled: bool) -> None:
        if enabled:
            command = "set python print-stack full"
        else:
            command = "set python print-stack message"

        gdb.execute(command, from_tty=True, to_string=True)
