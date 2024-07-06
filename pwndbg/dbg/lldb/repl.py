"""
LLDB does not normally allow us to replace built-in commands or do any sort of
hooking into the prompt. Pwndbg does need this, so, we write our own thin REPL
that takes care of that.
"""

import io
import os
import pwndbg
import pwndbg.dbg.lldb

from typing import List
from typing import Tuple
from typing_extensions import override


class InputFileProxy(io.TextIOBase):
    inner: io.TextIOBase
    
    def __init__(self, inner: io.TextIOBase):
        self.inner = inner

    @override
    def close(self) -> None:
        return self.inner.close()

    @override
    @property
    def closed(self) -> bool:
        return self.inner.closed

    @override
    def fileno(self) -> int:
        return self.inner.fileno()

    @override
    def flush(self) -> None:
        return self.inner.flush()

    @override
    def isatty(self) -> bool:
        return self.inner.isatty()

    @override
    def readable(self) -> bool:
        return self.inner.readable()

    @override
    def read(self, size: int = -1, /) -> str:
        return self.inner.read(size)

    @override
    def readline(self, size: int = -1, /) -> str:
        return self.inner.readline(size)

    @override
    def readlines(self, hint: int = -1, /) -> List[str]:
        return self.inner.readlines(hint)

    @override
    def seek(offset: int, whence: int = os.SEEK_SET, /) -> int:
        raise RuntimeError("seeking an input file proxy is not allowed")

    @override
    def seekable(self) -> bool:
        return False

    @override
    def tell(self) -> int:
        return 0

    @override
    def truncate(self, size: int = None, /) -> int:
        raise RuntimeError("truncating an input file proxy is not allowed")

    @override
    def writable(self) -> bool:
        return False

    @override
    def __del__(self) -> None:
        return self.inner.__del__()

    @override
    @property
    def encoding(self) -> str:
        return self.inner.encoding

    @override
    @property
    def errors(self) -> str:
        return self.inner.errors

    @override
    @property
    def newlines(self) -> str | Tuple[str, ...] | None:
        return self.inner.newlines

    @override
    def detach(self) -> None:
        raise NotImplementedError()


class CommandLineProxy(InputFileProxy):
    lldb: pwndbg.dbg_mod.lldb.LLDB

    def __init__(self, inner: io.TextIOBase, lldb: pwndbg.dbg_mod.lldb.LLDB):
        self.lldb = lldb
        super().__init__(inner)

    @override
    def read(self, size: int = -1, /) -> str:
        print(f"read {size}")
        return super().read(size)

    @override
    def readline(self, size: int = -1, /) -> str:
        print(f"readline {size}")
        return super().readline(size)

    @override
    def readlines(self, size: int = -1, /) -> str:
        print(f"readlines {size}")
        return super().readlines(size)

