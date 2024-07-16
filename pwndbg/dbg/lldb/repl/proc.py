from __future__ import annotations

import os
from typing import List

import lldb

from pwndbg.dbg.lldb.repl.io import IODriver


class EventHandler:
    """
    The event types that make sense for us to track in the process driver aren't
    the same as the ones in the rest of Pwndbg, so we just expose the native
    events in process driver, and let the rest of the REPL deal with any
    complexities that might arise from the translation.

    This is mostly intended to keep the complexity of generating the START and
    NEW_THREAD events correctly out of the process driver.
    """

    def created(self):
        """
        This function is called when a process is created or attached to.
        """
        pass

    def suspended(self):
        """
        This function is called when the execution of a process is suspended.
        """
        pass

    def resumed(self):
        """
        This function is called when the execution of a process is resumed.
        """
        pass

    def exited(self):
        """
        This function is called when a process terminates or is detached from.
        """
        pass

    def modules_loaded(self):
        """
        This function is called when a new modules have been loaded.
        """
        pass


class ProcessDriver:
    """
    Drives the execution of a process, responding to its events and handling its
    I/O, and exposes a simple synchronous interface to the REPL interface.
    """

    io: IODriver
    process: lldb.SBProcess
    listener: lldb.SBListener
    debug: bool
    eh: EventHandler

    def __init__(self, event_handler: EventHandler, debug=False):
        self.io = None
        self.process = None
        self.listener = None
        self.debug = debug
        self.eh = event_handler

    def has_process(self) -> bool:
        """
        Whether there's an active process in this driver.
        """
        return self.process is not None

    def interrupt(self) -> None:
        assert self.has_process(), "called interrupt() on a driver with no process"
        self.process.SendAsyncInterrupt()

    def _run_until_next_stop(
        self,
        with_io: bool = True,
        timeout: int = 1,
        first_timeout: int = 1,
        only_if_started: bool = False,
    ):
        """
        Runs the event loop of the process until the next stop event is hit, with
        a configurable timeouts for the first and subsequent timeouts.

        Optionally runs the I/O system alongside the event loop.

        If `only_if_started` is passed, this method will stop after the first
        timeout if it can't observe a state change to a running state, and I/O
        will only start running after the start event is observed.
        """

        # If `only_if_started` is set, we defer the starting of the I/O driver
        # to the moment the start event is observed. Otherwise, we just start it
        # immediately.
        io_started = False
        if with_io and not only_if_started:
            self.io.start(process=self.process)
            io_started = True

        # Pick the first timeout value.
        timeout_time = first_timeout

        # If `only_if_started` is not set, assume the process must have been
        # started by a previous action and is running.
        running = not only_if_started

        while True:
            event = lldb.SBEvent()
            if not self.listener.WaitForEvent(timeout_time, event):
                if self.debug:
                    print(f"[-] ProcessDriver: Timed out after {timeout_time}s")
                timeout_time = timeout

                # If the process isn't running, we should stop.
                if not running:
                    if self.debug:
                        print(
                            "[-] ProcessDriver: Waited too long for process to start running, giving up"
                        )
                    break

                continue

            if self.debug:
                descr = lldb.SBStream()
                if event.GetDescription(descr):
                    print(f"[-] ProcessDriver: {descr.GetData()}")
                else:
                    print(f"[!] ProcessDriver: No description for {event}")

            if lldb.SBTarget.EventIsTargetEvent(event):
                if event.GetType() == lldb.SBTarget.eBroadcastBitModulesLoaded:
                    # Notify the event handler that new modules got loaded in.
                    self.eh.modules_loaded()

            elif lldb.SBProcess.EventIsProcessEvent(event):
                if (
                    event.GetType() == lldb.SBProcess.eBroadcastBitSTDOUT
                    or event.GetType() == lldb.SBProcess.eBroadcastBitSTDERR
                ):
                    # Notify the I/O driver that the process might have something
                    # new for it to consume.
                    self.io.on_output_event()
                elif event.GetType() == lldb.SBProcess.eBroadcastBitStateChanged:
                    # The state of the process has changed.
                    new_state = lldb.SBProcess.GetStateFromEvent(event)
                    was_resumed = lldb.SBProcess.GetRestartedFromEvent(event)

                    if new_state == lldb.eStateStopped and not was_resumed:
                        # The process has stopped, so we're done processing events
                        # for the time being. Trigger the stopped event and return.
                        self.eh.suspended()
                        break

                    if new_state == lldb.eStateRunning or new_state == lldb.eStateStepping:
                        running = True
                        # Trigger the continued event.
                        self.eh.resumed()

                        # Start the I/O driver here if its start got deferred
                        # because of `only_if_started` being set.
                        if only_if_started and with_io:
                            self.io.start(process=self.process)
                            io_started = True

                    if (
                        new_state == lldb.eStateExited
                        or new_state == lldb.eStateCrashed
                        or new_state == lldb.eStateDetached
                    ):
                        # Nothing else for us to do here. Clear our internal
                        # references to the process, fire the exit event, and leave.
                        if self.debug:
                            print(f"[-] ProcessDriver: Process exited with state {new_state}")
                        self.process = None
                        self.listener = None

                        self.eh.exited()

                        break

        if io_started:
            self.io.stop()

    def cont(self) -> None:
        """
        Continues execution of the process this object is driving, and returns
        whenever the process stops.
        """
        assert self.has_process(), "called cont() on a driver with no process"

        self.process.Continue()
        self._run_until_next_stop()

    def run_lldb_command(self, command: str) -> None:
        """
        Runs the given LLDB command and ataches I/O if necessary.
        """
        assert self.has_process(), "called run_lldb_command() on a driver with no process"

        self.process.GetTarget().GetDebugger().HandleCommand(command)

        # We're banking here on HandleCommand resuming the process before it
        # returns. It seems to be the case that it always does it, but I can't
        # completely confirm it.
        #
        # If we get any reports of people having issues with commands not
        # resuming when they absolutely should, one should try increasing the
        # value of `first_timeout` here.
        self._run_until_next_stop(first_timeout=0, only_if_started=True)

    def launch(
        self, target: lldb.SBTarget, io: IODriver, env: List[str], args: List[str], working_dir: str
    ) -> lldb.SBError:
        """
        Launches the process and handles startup events. Always stops on first
        opportunity, and returns immediately after the process has stopped.
        """
        stdin, stdout, stderr = io.stdio()
        error = lldb.SBError()
        self.listener = lldb.SBListener("pwndbg.dbg.lldb.repl.proc.ProcessDriver")
        assert self.listener.IsValid()

        # We are interested in handling certain target events synchronously, so
        # set them up here, before LLDB has had any chance to do anything to the
        # process.
        self.listener.StartListeningForEventClass(
            target.GetDebugger(),
            lldb.SBTarget.GetBroadcasterClassName(),
            lldb.SBTarget.eBroadcastBitModulesLoaded,
        )

        # Do the launch, proper. We always stop the target, and let the upper
        # layers deal with the user wanting the program to not stop at entry by
        # calling `cont()`.
        self.process = target.Launch(
            self.listener,
            args,
            env,
            stdin,
            stdout,
            stderr,
            os.getcwd(),
            lldb.eLaunchFlagStopAtEntry,
            True,
            error,
        )

        if not error.success:
            # Undo any initialization Launch() might've done.
            self.process = None
            self.listener = None
            return error

        assert self.listener.IsValid()
        assert self.process.IsValid()
        self.io = io

        self.eh.created()

        return error
