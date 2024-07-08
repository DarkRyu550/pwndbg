#!/usr/bin/env python3

import sys
import os
import subprocess
import re

from typing import List

def find_lldb_version() -> List[int]:
    """
    Parses the version string given to us by the LLDB executable.
    """
    lldb = subprocess.run(["lldb", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if lldb.returncode != 0:
        print(f"Could not find the LLDB Python Path: {lldb.stderr}", file=sys.stderr)
        sys.exit(1)
    output = lldb.stdout.decode("utf-8").strip()
    output = re.sub("[^0-9.]", "", output)

    return [int(component) for component in output.split(".")]


def find_lldb_python_path() -> str:
    """
    Finds the Python path pointed to by the LLDB executable.
    """
    lldb = subprocess.run(["lldb", "-P"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if lldb.returncode != 0:
        print(f"Could not find the LLDB Python Path: {lldb.stderr}", file=sys.stderr)
        sys.exit(1)

    folder = lldb.stdout.decode("utf-8").strip()
    if not os.path.exists(folder):
        print(f"Path pointed to by LLDB ('{folder}') does not exist", file=sys.stderr)
        sys.exit(1)
    
    return folder


if __name__ == "__main__":
    # Find the path for the LLDB Python bindings.
    path = find_lldb_python_path()
    sys.path.append(path)

    # Older LLDB versions crash newer versions of CPython on import, so check
    # for it, and stop early with an error message.
    #
    # See https://github.com/llvm/llvm-project/issues/70453
    lldb_version = find_lldb_version()

    if sys.version_info.minor >= 12 and lldb_version[0] <= 18:
        print(f"LLDB 18 and earlier is incompatible with Python 3.12 and later", file=sys.stderr)
        sys.exit(1)

    # Start up LLDB and create a new debugger object.
    import lldb
    lldb.SBDebugger.Initialize()
    debugger = lldb.SBDebugger.Create()
    debugger.HandleCommand("command script import ./lldbinit.py")

    # Initialize the debugger, proper.
    import lldbinit
    lldbinit.main(debugger)

    # Run our REPL until the user decides to leave.
    if len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} [filename]", file=sys.stderr)
        sys.exit(1)

    target = None
    if len(sys.argv) == 2:
        target = sys.argv[1] 

    from pwndbg.dbg.lldb.repl import run as run_repl
    run_repl([f"target create {target}"] if target else None)

    # Dispose of our debugger and terminate LLDB.
    lldb.SBDebugger.Destroy(debugger)
    lldb.SBDebugger.Terminate()

