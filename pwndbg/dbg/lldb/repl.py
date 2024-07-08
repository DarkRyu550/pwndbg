"""
LLDB does not normally allow us to replace built-in commands or do any sort of
hooking into the prompt. Pwndbg does need this, so, we have our own thin REPL
that takes care of that.
"""

import io
import os
import pwndbg
import pwndbg.dbg.lldb
import gnureadline as readline

from typing import List
from typing import Tuple
from typing_extensions import override

from pwndbg.color import message

import lldb

def run(startup: List[str] | None = None) -> None:
    """
    Runs the Pwndbg REPL under LLDB. Optionally enters the commands given in
    `startup` as part of the startup process.
    """
    startup = startup if startup else []
    readline.parse_and_bind("")

    assert isinstance(pwndbg.dbg, pwndbg.dbg_mod.lldb.LLDB)
    dbg: pwndbg.dbg_mod.lldb.LLDB = pwndbg.dbg

    startup_i = 0
    while True:
        # Execute the prompt hook and ask for input.
        dbg._prompt_hook()
        try:
            print(message.prompt("pwndbg-lldb> "), end="")
            if startup_i < len(startup):
                line = startup[startup_i]
                print(line)
                startup_i += 1
            else:
                line = input()
        except EOFError:
            # Exit the REPL if there's nothing else to run.
            print()
            break
        line = line.strip()
        bits = line.split()

        if len(line) == 0:
            continue

        # There are interactive commands that `SBDebugger.HandleCommand` will
        # silently ignore. We have to implement them manually, here.
        if "quit".startswith(line):
            break
        if line == "exit":
            break

        # `script` is a little weird. Unlike with the other commands we're
        # emulating, we actually need LLDB to spawn it for it to make sense
        # from the perspective of the user. This means we have to make
        # special arrangements for it.
        #
        # There is a way to get LLDB to properly handle interactive commands,
        # and that is to start an interactive session with
        # `SBDebugger.RunCommandInterpreter`, but that comes with its own
        # challenges:
        #     (1) Starting an interactive session on standard input is the
        #         best option from the perspective of the user, as they get
        #         full access to the Python interpreter's readline functions.
        #         However, we can't start a session running a command, which
        #         means we open up the possibility of the user breaking
        #         Pwndbg completely if they type in any process or target
        #         management commands.
        #     (2) Setting an input file up for the debugger to use, having
        #         that input file start the Python interpreter, and piping
        #         `sys.stdin` to it while the interpreter is running. This
        #         option is better in that it avoids the possibility of the
        #         user breaking Pwndbg by mistake, but it breaks both
        #         readline and input in general for the user.
        #
        # While neither option is ideal, both can be partially mitigated.
        # Option (1) by adding an extra command that drops down to LLDB and
        # prints a warning to make the user aware of the risk of breaking
        # Pwndbg, and option (2) by making a TextIOBase class that uses input()
        # at the REPL level before piping that to the Python interpreter running
        # under LLDB.
        #
        # Currently, we go with the mitigated version of option (1), but option
        # (2) might still be on the table for the near future.
        if bits[0].startswith("sc") and "script".startswith(bits[0]):
            print(message.error("The 'script' command is not supported. Use the 'lldb' command to enter LLDB mode and try again."))
            continue
        
        if bits[0] == "lldb":
            print(message.warn("You're entering LLDB mode. In this mode, certain commands may cause Pwndbg to break. Proceed with caution."))
            dbg.debugger.RunCommandInterpreter(True, False, lldb.SBCommandInterpreterRunOptions(), 0, False, False)
            continue

        # Because we need to capture events related to target setup and process
        # startup, we handle them here, in a special way.
        if bits[0].startswith("pr") and "process".startswith(bits[0]):
            if len(bits) > 1 and bits[1].startswith("la") and "launch".startswith(bits[1]):
                # This is `process launch`.
                print("Wooooo process launch")
                continue
            elif len(bits) > 1 and bits[1].startswith("a") and "attach".startswith(bits[1]):
                # This is `process attach`.
                print("Wooooo process attach")
                continue
            # We don't care about other process commands..

        if bits[0].startswith("ta") and "target".startswith(bits[0]):
            if len(bits) > 1 and bits[1].startswith("c") and "create".startswith(bits[1]):
                # This is `target create`
                print("Wooooo target create")
                continue
            elif len(bits) > 1 and bits[1].startswith("de") and "delete".startswith(bits[1]):
                # This is `target delete`
                print("Wooooo target delete")
                continue
        
        # The command hasn't matched any of our filtered commands, just let LLDB
        # handle it normally.
        dbg.debugger.HandleCommand(line)

target_create_ap = argparse.ArgumentParser()
target_create_ap.add_argument("-S", "--sysroot")
target_create_ap.add_argument("-a", "--arch")
target_create_ap.add_argument("-b", "--build")
target_create_ap.add_argument("-c", "--sysroot")
target_create_ap.add_argument("-d", "--sysroot")
target_create_ap.add_argument("-p", "--sysroot")
target_create_ap.add_argument("-r", "--sysroot")
target_create_ap.add_argument("-s", "--sysroot")
target_create_ap.add_argument("-v", "--sysroot")

def target_create():

