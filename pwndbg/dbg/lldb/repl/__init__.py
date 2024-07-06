"""
The Pwndbg REPL that is the interface to all debugging on LLDB.

Pwndbg has an event system that allows it to react to events in the process
being debugged, such as when new executable modules get added to the its address
space, when the value of memory and registers change, and pretty much all
possible changes to its execution state. We'd like to have the event system work
the same way under LLDB as it does under GDB.

Fortunately for us, the events types that are native to LLDB map really well to
the event types in GDB and Pwndbg. Very, very unfortunately for us, however,
that's basically where our luck ends.

LLDB, as of version 18, only provides two ways to capture events: registering
directly with the broadcaster, or registering globally. The former is not
available to us in the standard LLDB REPL, as we don't get access to the process
object until after it's been launched[1]. Likewise for the latter, as the
interactive debugger will register to receive the global process state change
events before everyone else, and LLDB doesn't allow for multiple listeners for
the same event bits in the same event class[2].

This leaves us with handling process management ourselves as the only option we
really have to implement event dispatch in Pwndbg. Easy, right? We can just
hijack the commands that deal with target and process creation, and leave
everything else untouched. Unfortunately for us, again, shadowing builtin
commands is simply not allowed[3][4].

So, really, all that's left for us is either implement our own REPL, or get rid
of the event system.

[1]: https://discourse.llvm.org/t/understanding-debugger-launch-events-sequence/39717/2
[2]: https://github.com/llvm/llvm-project/blob/3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff/lldb/source/Utility/Broadcaster.cpp#L409
[3]: https://github.com/llvm/llvm-project/blob/3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff/lldb/source/Commands/CommandObjectCommands.cpp#L439
[4]: https://github.com/llvm/llvm-project/blob/3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff/lldb/source/Interpreter/CommandInterpreter.cpp#L1157
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import threading
from typing import Any
from typing import List
from typing import Tuple

import lldb

import pwndbg
import pwndbg.dbg.lldb
from pwndbg.color import message
from pwndbg.dbg.lldb import LLDB
from pwndbg.dbg.lldb.repl.io import IODriver
from pwndbg.dbg.lldb.repl.io import get_io_driver
from pwndbg.dbg.lldb.repl.proc import ProcessDriver
from pwndbg.dbg.lldb.repl.readline import PROMPT
from pwndbg.dbg.lldb.repl.readline import disable_readline
from pwndbg.dbg.lldb.repl.readline import enable_readline

# We only allow certain commands to be executed in LLDB mode. This list contains
# tuples made up of the full name of the command and functions that check if a
# given command matches it.
LLDB_EXCLUSIVE = [
    ("script", lambda cmd: cmd.startswith("sc") and "script".startswith(cmd)),
    ("expression", lambda cmd: cmd.startswith("e") and "expression".startswith(cmd)),
]


def lex_args(args: str) -> List[str]:
    """
    Splits the arguments, respecting quotation marks.
    """
    args = args.strip()
    result = []
    while len(args) > 0:
        first = re.match("\\s*(\".*\"|'.*'|\\S+)", args)
        sl = first[1]

        # Handle single and double quotes, we could do some escaping for the
        # double quotes case, but we don't, yet.
        sl = sl.strip('"')
        sl = sl.strip("'")

        result.append(sl)
        args = args[first.end() :]

    return result


def run(startup: List[str] | None = None) -> None:
    """
    Runs the Pwndbg REPL under LLDB. Optionally enters the commands given in
    `startup` as part of the startup process.
    """

    assert isinstance(pwndbg.dbg, LLDB)
    dbg: LLDB = pwndbg.dbg

    startup = startup if startup else []
    startup_i = 0

    enable_readline(dbg)

    # We're gonna be dealing with process events ourselves, so we'll want to run
    # LLDB in asynchronous mode.
    dbg.debugger.SetAsync(True)

    # This is the driver we're going to be using to handle the process.
    driver = ProcessDriver(debug=True)

    # Set ourselves up to respond to SIGINT by interrupting the process if it is
    # running, and doing nothing otherwise.
    def handle_sigint(_sig, _frame):
        if driver.has_process():
            driver.interrupt()
            print()

    signal.signal(signal.SIGINT, handle_sigint)

    while True:
        # Execute the prompt hook and ask for input.
        dbg._prompt_hook()
        try:
            if startup_i < len(startup):
                print(PROMPT, end="")
                line = startup[startup_i]
                print(line)
                startup_i += 1
            else:
                line = input(PROMPT)
        except EOFError:
            # Exit the REPL if there's nothing else to run.
            print()
            break
        bits = lex_args(line)

        if len(line) == 0:
            continue

        # Let the user get an LLDB prompt if they so desire.
        if bits[0] == "lldb":
            print(
                message.warn(
                    "You are now entering LLDB mode. In this mode, certain commands may cause Pwndbg to break. Proceed with caution."
                )
            )
            dbg.debugger.RunCommandInterpreter(
                True, False, lldb.SBCommandInterpreterRunOptions(), 0, False, False
            )
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
        #
        # Likewise for the other commands we barr here.
        found_barred = False
        for name, test in LLDB_EXCLUSIVE:
            if not test(bits[0]):
                continue

            print(
                message.error(
                    f"The '{name}' command is not supported. Use the 'lldb' command to enter LLDB mode and try again."
                )
            )

            found_barred = True

        if found_barred:
            continue

        # Because we need to capture events related to target setup and process
        # startup, we handle them here, in a special way.
        if bits[0].startswith("pr") and "process".startswith(bits[0]):
            if len(bits) > 1 and bits[1].startswith("la") and "launch".startswith(bits[1]):
                # This is `process launch`.
                process_launch(driver, bits[2:], dbg)
                continue
            if len(bits) > 1 and bits[1].startswith("a") and "attach".startswith(bits[1]):
                # This is `process attach`.
                #
                # TODO: Implement process attach.
                print(message.error("Pwndbg does not support 'process attach' yet."))
                continue
            # We don't care about other process commands..

        if bits[0].startswith("ta") and "target".startswith(bits[0]):
            if len(bits) > 1 and bits[1].startswith("c") and "create".startswith(bits[1]):
                # This is `target create`
                target_create(bits[2:], dbg)
                continue
            if len(bits) > 1 and bits[1].startswith("de") and "delete".startswith(bits[1]):
                # This is `target delete`
                #
                # Currently, this check is here but it does nothing. We might
                # need to check for this, but I can't figure out what kind of
                # processing we should do for its arguments, so we do nothing.
                pass

        if bits[0].startswith("r") and "run".startswith(bits[0]):
            # `run` is an alias for `process launch`
            process_launch(driver, bits[1:], dbg)
            continue

        if bits[0] == "c" or (bits[0].startswith("con") and "continue".startswith(bits[0])):
            # Handle `continue` manually. While `ProcessDriver.run_lldb_command`
            # is more than capable of handling this command itself, there's no
            # need for it to. We know what the user wants, so we can fast-track
            # their request.
            continue_process(driver, bits[1:], dbg)
            continue

        # The command hasn't matched any of our filtered commands, just let LLDB
        # handle it normally. Either in the context of the process, if we have
        # one, or just in a general context.
        if driver.has_process():
            driver.run_lldb_command(line)
        else:
            dbg.debugger.HandleCommand(line)


def make_pty() -> Tuple[str, int]:
    """
    We need to make a pseudo-terminal ourselves if we want the process to handle
    naturally for the user. Returns a tuple with the filaname and the file
    descriptor if successful.
    """
    import ctypes

    libc = ctypes.CDLL("libc.so.6")
    pty = libc.posix_openpt(2)
    if pty <= 0:
        return None

    libc.ptsname.restype = ctypes.c_char_p
    name = libc.ptsname(pty)

    if libc.unlockpt(pty) != 0:
        libc.close(pty)
        return None

    return name, pty


def parse(args: List[str], parser: argparse.ArgumentParser, unsupported: List[str]) -> Any | None:
    """
    Parses a list of string arguments into an object containing the parsed
    data.
    """
    try:
        args = parser.parse_args(args)
    except SystemExit:
        # Ugly, but need to keep ArgumentParser from terminating the process.
        return None

    # Reject any arguments we don't know how to handle yet.
    #
    # We'd like this list to grow over time, but we don't strictly need to
    # support all of these right away.
    varsargs = vars(args)
    for unsup in unsupported:
        if varsargs[unsup.replace("-", "_")]:
            print(message.error(f"Pwndbg does not support --{unsup} yet"))
            return None

    return args


target_create_ap = argparse.ArgumentParser(add_help=False)
target_create_ap.add_argument("-S", "--sysroot")
target_create_ap.add_argument("-a", "--arch")
target_create_ap.add_argument("-b", "--build")
target_create_ap.add_argument("-c", "--core")
target_create_ap.add_argument("-d", "--no-dependents")
target_create_ap.add_argument("-p", "--platform")
target_create_ap.add_argument("-r", "--remote-file")
target_create_ap.add_argument("-s", "--symfile")
target_create_ap.add_argument("-v", "--version")
target_create_ap.add_argument("filename")
target_create_unsupported = [
    "sysroot",
    "arch",
    "build",
    "core",
    "no-dependents",
    "platform",
    "remote-file",
    "symfile",
    "version",
]


def target_create(args: List[str], dbg: LLDB) -> None:
    """
    Creates a new target, registers it with the Pwndbg LLDB implementation, and
    sets up listeners for it.
    """
    args = parse(args, target_create_ap, target_create_unsupported)
    if not args:
        return

    if dbg.debugger.GetNumTargets() > 0:
        print(
            message.error(
                "Pwndbg does not support multiple targets. Please remove the current target with 'target delete' and try again."
            )
        )
        return

    # Create the target with the debugger.
    target = dbg.debugger.CreateTarget(args.filename)
    if not target.IsValid():
        print(message.error(f"could not create target for '{args.filename}'"))
        return

    dbg.debugger.SetSelectedTarget(target)

    print(f"Current executable set to '{args.filename}' ({target.triple.split('-')[0]})")
    return


process_launch_ap = argparse.ArgumentParser(add_help=False)
process_launch_ap.add_argument("-A", "--disable-aslr")
process_launch_ap.add_argument("-C", "--script-class")
process_launch_ap.add_argument("-E", "--environment")
process_launch_ap.add_argument("-P", "--plugin")
process_launch_ap.add_argument("-X", "--shell-expand-args")
process_launch_ap.add_argument("-a", "--arch")
process_launch_ap.add_argument("-c", "--shell")
process_launch_ap.add_argument("-e", "--stderr")
process_launch_ap.add_argument("-i", "--stdin")
process_launch_ap.add_argument("-k", "--structured-data-key")
process_launch_ap.add_argument("-n", "--no-stdio")
process_launch_ap.add_argument("-o", "--stdout")
process_launch_ap.add_argument("-s", "--stop-at-entry", action="store_true")
process_launch_ap.add_argument("-t", "--tty")
process_launch_ap.add_argument("-v", "--structured-data-value")
process_launch_ap.add_argument("-w", "--working-dir")
process_launch_ap.add_argument("run-args", nargs="*")
process_launch_unsupported = [
    "disable-aslr",
    "script-class",
    "environment",
    "plugin",
    "shell-expand-args",
    "arch",
    "shell",
    "stderr",
    "stdin",
    "structured-data-key",
    "no-stdio",
    "stdout",
    "tty",
    "structured-data-value",
    "working-dir",
]


def process_launch(driver: ProcessDriver, args: List[str], dbg: LLDB) -> None:
    """
    Launches a process with the given arguments, and returns the process itself
    and its event listener if the launch was successful. Returns `None` otherwise.
    """
    args = parse(args, process_launch_ap, process_launch_unsupported)
    if not args:
        return

    targets = dbg.debugger.GetNumTargets()
    assert targets < 2
    if targets == 0:
        print(
            message.error(
                "error: invalid target, create a target using the 'target create' command"
            )
        )
        return

    if driver.has_process():
        print(message.error("error: a process is already being debugged"))
        return

    io_driver = get_io_driver()
    result = driver.launch(dbg.debugger.GetTargetAtIndex(0), io_driver, [], [], os.getcwd())

    if not result.success:
        print(message.error(f"Could not launch process: {result.description}"))
        return

    # Continue execution if the user hasn't requested for a stop at the entry
    # point of the process.
    if not args.stop_at_entry:
        driver.cont()


continue_ap = argparse.ArgumentParser(add_help=False)
continue_ap.add_argument("-i", "--ignore-count")
continue_unsupported = ["ignore-count"]


def continue_process(driver: ProcessDriver, args: List[str], dbg: LLDB) -> None:
    """
    Continues the execution of a process.
    """
    args = parse(args, continue_ap, continue_unsupported)
    if not args:
        return

    if not driver.has_process():
        print(
            message.error(
                "error: invalid target, create a target using the 'target create' command"
            )
        )
        return

    driver.cont()
