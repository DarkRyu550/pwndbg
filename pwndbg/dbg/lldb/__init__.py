from __future__ import annotations

import os
import random
import sys
from typing import Any
from typing import Callable
from typing import List
from typing import Sequence
from typing import Tuple

import lldb
from typing_extensions import override

import pwndbg


class LLDBFrame(pwndbg.dbg_mod.Frame):
    def __init__(self, inner: lldb.SBFrame):
        self.inner = inner

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        value = self.inner.EvaluateExpression(expression)
        opt_out = _is_optimized_out(value)

        if not value.error.Success() and not opt_out:
            raise pwndbg.dbg_mod.Error(value.error.description)

        return LLDBValue(value)


def map_type_code(type: lldb.SBType) -> pwndbg.dbg_mod.TypeCode:
    """
    Determines the type code of a given LLDB SBType.
    """
    c = type.GetTypeClass()
    f = type.GetTypeFlags()

    assert c != lldb.eTypeClassInvalid, "passed eTypeClassInvalid to map_type_code"

    if c == lldb.eTypeClassUnion:
        return pwndbg.dbg_mod.TypeCode.UNION
    if c == lldb.eTypeClassStruct:
        return pwndbg.dbg_mod.TypeCode.STRUCT
    if c == lldb.eTypeClassTypedef:
        return pwndbg.dbg_mod.TypeCode.TYPEDEF
    if c == lldb.eTypeClassPointer:
        return pwndbg.dbg_mod.TypeCode.POINTER
    if c == lldb.eTypeClassArray:
        return pwndbg.dbg_mod.TypeCode.ARRAY

    if f & lldb.eTypeIsInteger != 0:
        return pwndbg.dbg_mod.TypeCode.INT

    raise RuntimeError("missing mapping for type code")


def _is_optimized_out(value: lldb.SBValue) -> bool:
    """
    Returns whether the given value is likely to have been optimized out.
    """

    # We use this rather hacky way to distinguish if expressions that
    # contain values that have been optimized out, from those that are truly
    # invalid.
    #
    # Obviously, this is a rather bad solution, and breaks if the version of
    # LLDB we're running under is not in English, or if this message gets
    # changed in the future.
    #
    # LLDB does internally have a way to distinguish the invalid expression
    # case from the optimized-out one, through lldb::ExpressionResults, but
    # there does not seem to be a way to wrangle one out of
    # EvaluateExpression.
    #
    # In case this fails, we fall back to treating expression containing
    # optimized-out values the same way we treat invalid expressions, which
    # shoulnd't really be that bad.
    return value.error.description and "optimized out" in value.error.description


class LLDBType(pwndbg.dbg_mod.Type):
    inner: lldb.SBType

    def __init__(self, inner: lldb.SBType):
        self.inner = inner

    @property
    @override
    def sizeof(self) -> int:
        return self.inner.GetByteSize()

    @property
    @override
    def alignof(self) -> int:
        return self.inner.GetByteAlign()

    @property
    @override
    def code(self) -> pwndbg.dbg_mod.TypeCode:
        return map_type_code(self.inner)

    @override
    def fields(self) -> List[pwndbg.dbg_mod.TypeField] | None:
        fields = self.inner.get_fields_array()
        return (
            [
                pwndbg.dbg_mod.TypeField(
                    field.bit_offset,
                    field.name,
                    LLDBType(field.type),
                    self,
                    0,  # TODO: Handle fields for enum types differently.
                    False,
                    False,  # TODO: Handle base class members differently.
                    field.bitfield_bit_size if field.is_bitfield else field.type.GetByteSize(),
                )
                for field in fields
            ]
            if len(fields) > 0
            else None
        )

    @override
    def array(self, count: int) -> pwndbg.dbg_mod.Type:
        return LLDBType(self.inner.GetArrayType(count))

    @override
    def pointer(self) -> pwndbg.dbg_mod.Type:
        return LLDBType(self.inner.GetPointerType())

    @override
    def strip_typedefs(self) -> pwndbg.dbg_mod.Type:
        t = self.inner
        while t.IsTypedefType():
            t = t.GetTypedefedType

        return LLDBType(t)

    @override
    def target(self) -> pwndbg.dbg_mod.Type:
        t = self.inner.GetPointeeType()
        if not t.IsValid():
            raise pwndbg.dbg_mod.Error("tried to get target type of non-pointer type")

        return LLDBType(t)


class LLDBValue(pwndbg.dbg_mod.Value):
    def __init__(self, inner: lldb.SBValue):
        self.inner = inner

    @property
    @override
    def address(self) -> pwndbg.dbg_mod.Value | None:
        addr = self.inner.AddressOf()
        return LLDBValue(addr) if addr.IsValid() else None

    @property
    @override
    def is_optimized_out(self) -> bool:
        return _is_optimized_out(self.inner)

    @property
    @override
    def type(self) -> pwndbg.dbg_mod.Type:
        assert not self.is_optimized_out, "tried to get type of optimized-out value"

        return LLDBType(self.type)

    @override
    def dereference(self) -> pwndbg.dbg_mod.Value:
        deref = self.inner.Dereference()

        if not deref.IsValid():
            raise pwndbg.dbg_mod.Error("could not dereference value")

        return LLDBValue(deref)

    @override
    def string(self) -> str:
        addr = self.inner.unsigned
        error = lldb.SBError()

        # Read strings up to 4GB.
        last_str = None
        buf = 256
        for i in range(8, 33):
            s = self.inner.process.ReadCStringFromMemory(addr, buf, error)
            if error.Fail():
                raise pwndbg.dbg_mod.Error(f"could not read value as string: {error.description}")
            if last_str is not None and len(s) == len(last_str):
                break
            last_str = s

            buf *= 2

        return last_str

    @override
    def fetch_lazy(self) -> None:
        # Not needed under LLDB.
        pass

    @override
    def __int__(self) -> int:
        return self.inner.signed

    @override
    def cast(self, type: pwndbg.dbg_mod.Type | Any) -> pwndbg.dbg_mod.Value:
        assert isinstance(type, LLDBType)
        t: LLDBType = type

        return LLDBValue(self.inner.Cast(t.inner))


class LLDBMemoryMap(pwndbg.dbg_mod.MemoryMap):
    def __init__(self, pages: List[pwndbg.lib.memory.Page]):
        self.pages = pages

    @override
    def is_qemu(self) -> bool:
        # Figure a way to detect QEMU later.
        return False

    @override
    def has_reliable_perms(self) -> bool:
        return True

    @override
    def ranges(self) -> List[pwndbg.lib.memory.Page]:
        return self.pages


class LLDBProcess(pwndbg.dbg_mod.Process):
    def __init__(self, process: lldb.SBProcess, target: lldb.SBTarget):
        self.process = process
        self.target = target

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        value = self.target.EvaluateExpression(expression)
        opt_out = _is_optimized_out(value)

        if not value.error.Success() and not opt_out:
            raise pwndbg.dbg_mod.Error(value.error.description)

        return LLDBValue(value)

    @override
    def vmmap(self) -> pwndbg.dbg_mod.MemoryMap:
        regions = self.process.GetMemoryRegions()

        pages = []
        for i in range(regions.GetSize()):
            region = lldb.SBMemoryRegionInfo()
            assert regions.GetMemoryRegionAtIndex(
                i, region
            ), "invalid region despite being in bounds"

            perms = 0
            if region.IsReadable():
                perms |= os.R_OK
            if region.IsWritable():
                perms |= os.W_OK
            if region.IsExecutable():
                perms |= os.X_OK

            # LLDB doesn't actually tell us the offset of a mapped file.
            offset = 0

            pages.append(
                pwndbg.lib.memory.Page(
                    start=region.GetRegionBase(),
                    size=region.GetRegionEnd() - region.GetRegionBase(),
                    flags=perms,
                    offset=offset,
                    objfile=region.GetName(),
                )
            )

        return LLDBMemoryMap(pages)

    def find_largest_range_len(
        self, min_search: int, max_search: int, test: Callable[[int], bool]
    ) -> int:
        """
        Finds the largest memory range given a minimum and a maximum value
        for the size of the rage. This is a binary search, so it should do on
        the order of log2(max_search - min_search) attempts before it arrives at
        an answer.
        """
        # See if there's even any region we could possibly read.
        r = max_search - min_search
        if r == 0:
            return min_search if test(min_search) else 0

        # Pick the midpoint from our previous search.
        mid_search = min_search + r // 2

        if not test(mid_search):
            # No dice. This means the limit of the mapping must come before the
            # midpoint.
            return self.find_largest_range_len(min_search, mid_search, test)

        # We can read this range. This means that the limit of the mapping must
        # come after the midpoint, or be equal to it, exactly.
        after = self.find_largest_range_len(mid_search + 1, max_search, test)
        if after > 0:
            # It came after the midpoint.
            return after

        # We are exactly at the limit.
        return min_search

    @override
    def read_memory(self, address: int, size: int, partial: bool = False) -> bytearray:
        if size == 0:
            return bytearray()

        # Try to read exactly the requested size.
        e = lldb.SBError()
        buffer = self.process.ReadMemory(address, size, e)
        if buffer:
            return buffer
        elif not partial:
            raise pwndbg.dbg_mod.Error(f"could not read {size:#x} bytes: {e}")

        # At this point, we're in a bit of a pickle. LLDB doesn't give us enough
        # information to find out what the last address it can read from is. For
        # all we know, it could be any address in the range (address, address+size),
        # so we have to get creative.
        #
        # First, try to derive that information from the mmap.
        first_page = None
        last_page = None
        vmmap_size = 0
        for page in self.vmmap().ranges():
            if address in page and not first_page:
                first_page = page
                last_page = page
                size = page.memsz - (address - page.start)
            elif last_page:
                if page.start <= last_page.end:
                    last_page = page
                    size += page.memsz
                else:
                    break

        if vmmap_size > 0:
            try:
                return self.read_memory(address, vmmap_size, partial=False)
            except pwndbg.dbg_mod.Error:
                # Unreliable memory map?
                pass

        # Second, try to do a binary search for the limit of the range.
        def test(s):
            b = self.process.ReadMemory(address, s, e)
            return b is not None

        size = self.find_largest_range_len(0, size, test)
        if size > 0:
            return bytearray(self.process.ReadMemory(address, size, e))
        else:
            return bytearray()

    @override
    def write_memory(self, address: int, data: bytearray, partial: bool = False) -> int:
        if len(data) == 0:
            return 0

        e = lldb.SBError()
        count = self.process.WriteMemory(address, data, e)
        if count < len(data) and not partial:
            raise pwndbg.dbg_mod.Error(f"could not write {len(data)} bytes: {e}")

        return count

    @override
    def create_value(
        self, value: int, type: pwndbg.dbg_mod.Type | None = None
    ) -> pwndbg.dbg_mod.Value:
        import struct

        b = struct.pack("<Q", value)

        e = lldb.SBError()
        data = lldb.SBData()
        data.SetDataWithOwnership(e, b, lldb.eByteOrderLittle, len(b))

        import pwndbg.aglib.typeinfo

        u64 = pwndbg.aglib.typeinfo.uint64

        assert u64, "aglib.typeinfo must have already been set up"
        assert isinstance(u64, LLDBType), "aglib.typeinfo contains non-LLDBType values"
        u64: LLDBType = u64

        value = self.target.CreateValueFromData("#0", data, u64.inner)
        value = LLDBValue(value)

        if type:
            return value.cast(type)
        else:
            return value

    @override
    def symbol_name_at_address(self, address: int) -> str | None:
        addr = lldb.SBAddress(address, self.target)
        ctx = self.target.ResolveSymbolContextForAddress(addr, lldb.eSymbolContextSymbol)

        if not ctx.IsValid():
            return None

        if not ctx.symbol.IsValid():
            return None

        return ctx.symbol.name

    def types_with_name(self, name: str) -> Sequence[pwndbg.dbg_mod.Type]:
        types = self.target.FindTypes(name)
        return [LLDBType(types.GetTypeAtIndex(i)) for i in range(types.GetSize())]


class LLDBCommand(pwndbg.dbg_mod.CommandHandle):
    def __init__(self, handler_name: str, command_name: str):
        self.handler_name = handler_name
        self.command_name = command_name


class LLDB(pwndbg.dbg_mod.Debugger):
    exec_states: List[lldb.SBExecutionState]

    @override
    def setup(self, *args):
        self.exec_states = []

        debugger = args[0]
        assert (
            debugger.__class__ is lldb.SBDebugger
        ), "lldbinit.py should call setup() with an lldb.SBDebugger object"

        module = args[1]
        assert module.__class__ is str, "lldbinit.py should call setup() with __name__"

        self.module = module
        self.debugger = debugger

        # Load all of our commands.
        import pwndbg.commands

        pwndbg.commands.load_commands()

        import pwndbg.dbg.lldb.pset

    @override
    def add_command(
        self, command_name: str, handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None]
    ) -> pwndbg.dbg_mod.CommandHandle:
        debugger = self

        class CommandHandler:
            def __init__(self, debugger, _):
                pass

            def __call__(self, _, command, exe_context, result):
                debugger.exec_states.append(exe_context)
                handler(debugger, command, True)
                assert (
                    debugger.exec_states.pop() == exe_context
                ), "Execution state mismatch on command handler"

        # LLDB is very particular with the object paths it will accept. It is at
        # its happiest when its pulling objects straight off the module that was
        # first imported with `command script import`, so, we install the class
        # we've just created as a global value in its dictionary.
        rand = round(random.random() * 0xFFFFFFFF) // 1
        rand = f"{rand:08x}"

        name = f"__{rand}_LLDB_COMMAND_{command_name}"
        print(f"adding command {command_name}, under the path {self.module}.{name}")

        sys.modules[self.module].__dict__[name] = CommandHandler

        # Install the command under the name we've just picked.
        self.debugger.HandleCommand(
            f"command script add -c {self.module}.{name} -s synchronous {command_name}"
        )

        return LLDBCommand(name, command_name)

    @override
    def history(self, last: int = 10) -> List[Tuple[int, str]]:
        # Figure out a way to retrieve history later.
        # Just need to parse the result of `self.inner.HandleCommand("history")`
        return []

    @override
    def commands(self) -> List[str]:
        # Figure out a way to retrieve the command list later.
        return []

    @override
    def lex_args(self, command_line: str) -> List[str]:
        return command_line.split()

    def first_inferior(self) -> LLDBProcess | None:
        """
        Pick the first inferior in the debugger, if any is present.
        """
        target_count = self.debugger.GetNumTargets()
        if target_count == 0:
            # No targets are available.
            return None
        if target_count > 1:
            # We don't support multiple targets.
            raise RuntimeError("Multiple LLDB targets are not supported")

        target = self.debugger.GetTargetAtIndex(0)
        assert target.IsValid(), "Target must be valid at this point"

        process = target.GetProcess()
        if not process.IsValid():
            # No process we can use.
            return None

        return LLDBProcess(process, target)

    @override
    def selected_inferior(self) -> pwndbg.dbg_mod.Process | None:
        if len(self.exec_states) == 0:
            # The Debugger-agnostic API treats existence of an inferior the same
            # as it being selected, as multiple inferiors are not supported, so
            # we lie a little here, and treat the only inferior as always
            # selected.
            return self.first_inferior()

        p = self.exec_states[-1].process
        t = self.exec_states[-1].target

        if p.IsValid() and t.IsValid():
            return LLDBProcess(p, t)

        return None

    @override
    def selected_frame(self) -> pwndbg.dbg_mod.Frame | None:
        if len(self.exec_states) == 0:
            return None

        f = self.exec_states[-1].frame
        if f.IsValid():
            return LLDBFrame(f)

        return None

    def _prompt_hook(self) -> None:
        """
        The REPL calls this function in order to signal that the prompt hooks
        should be executed.
        """
        pass

    @override
    def get_cmd_window_size(self) -> Tuple[int, int]:
        import pwndbg.ui

        return pwndbg.ui.get_window_size()

    def is_gdblib_available(self):
        return False

    @override
    def addrsz(self, address: Any) -> str:
        return "%#16x" % address

    @override
    def set_python_diagnostics(self, enabled: bool) -> None:
        pass
