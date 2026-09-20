from __future__ import annotations

import os
import shlex
import socket
import threading
from typing import Callable, Dict, List, Optional, Tuple


META_PREFIX = b"\x1eRUSTOS_META "
META_HELLO = b"RUSTOS_META_HELLO version=1\n"
META_MUX_HELLO = META_PREFIX + META_HELLO

HELLO_RETRY_SECONDS = 0.25


_console_lock = threading.Lock()


def _write_codelldb_console(debugger, text: str) -> None:
    try:
        from codelldb import interface as codelldb_interface

        stream = codelldb_interface.session_stdouts.get(debugger.GetID())

        if stream is None:
            return

        with _console_lock:
            stream.write(text)
            stream.flush()
    except Exception:
        return


class _Section:
    __slots__ = (
        "name",
        "addr",
        "size",
    )

    def __init__(
        self,
        name: str,
        addr: int,
        size: int,
    ) -> None:
        self.name = name
        self.addr = addr
        self.size = size


class _PendingModule:
    __slots__ = (
        "id",
        "name",
        "path",
        "preferred",
        "loaded",
        "sections",
    )

    def __init__(
        self,
        module_id: int,
        name: str,
        path: str,
        preferred: int,
        loaded: int,
    ) -> None:
        self.id = module_id
        self.name = name
        self.path = path
        self.preferred = preferred
        self.loaded = loaded
        self.sections: List[_Section] = []


class _LoadedModule:
    __slots__ = (
        "id",
        "name",
        "abs_path",
        "preferred",
        "loaded",
        "sections",
    )

    def __init__(
        self,
        module_id: int,
        name: str,
        abs_path: str,
        preferred: int,
        loaded: int,
        sections: List[_Section],
    ) -> None:
        self.id = module_id
        self.name = name
        self.abs_path = abs_path
        self.preferred = preferred
        self.loaded = loaded
        self.sections = sections


class _MetaProtocol:
    ACK_PREFIX = "RUSTOS_META_HELLO_ACK"

    def __init__(
        self,
        debugger,
        driver_dir: str,
    ) -> None:
        self._debugger = debugger

        self._driver_dir = (
            os.path.abspath(driver_dir)
            .replace("\\", "/")
        )

        self._loaded: Dict[
            Tuple[str, int],
            _LoadedModule,
        ] = {}

        self._pending: Dict[
            int,
            _PendingModule,
        ] = {}

        self._lldb_lock = threading.Lock()
        self._hello_acked = threading.Event()

        self._ready_sender: Optional[
            Callable[[int], bool]
        ] = None

    @property
    def driver_dir(self) -> str:
        return self._driver_dir

    @property
    def hello_acked(self) -> bool:
        return self._hello_acked.is_set()

    def set_ready_sender(
        self,
        sender: Callable[[int], bool],
    ) -> None:
        self._ready_sender = sender

    def process_line_bytes(
        self,
        line: bytes,
    ) -> None:
        try:
            text = (
                line.rstrip(b"\r")
                .decode(
                    "utf-8",
                    errors="replace",
                )
            )

            self._process_line(text)

        except Exception as exc:
            self._print(
                f"[rustos-meta] WARNING: {exc!r}"
            )

    def _process_line(
        self,
        line: str,
    ) -> None:
        if not line:
            return

        if line.startswith(
            self.ACK_PREFIX
        ):
            if not self._hello_acked.is_set():
                self._hello_acked.set()

                self._print(
                    "[rustos-meta] "
                    "kernel acknowledged hello — "
                    "snapshot incoming"
                )

            return

        if line.startswith(
            "RUSTOS_MODULE_BEGIN"
        ):
            self._handle_begin(line)

        elif line.startswith(
            "RUSTOS_MODULE_SECTION"
        ):
            self._handle_section(line)

        elif line.startswith(
            "RUSTOS_MODULE_END"
        ):
            self._handle_end(line)

    def _handle_begin(
        self,
        line: str,
    ) -> None:
        tokens = self._parse_kv(
            line,
            "RUSTOS_MODULE_BEGIN",
        )

        if tokens is None:
            return

        try:
            module_id = int(
                tokens["id"]
            )

            name = tokens["name"]

            path = tokens.get(
                "path",
                "",
            )

            preferred = int(
                tokens["preferred"],
                16,
            )

            loaded = int(
                tokens["loaded"],
                16,
            )

        except (
            KeyError,
            ValueError,
        ) as exc:
            self._print(
                "[rustos-meta] "
                "WARNING: bad MODULE_BEGIN "
                f"({exc!r}): {line!r}"
            )

            return

        self._pending[module_id] = (
            _PendingModule(
                module_id,
                name,
                path,
                preferred,
                loaded,
            )
        )

    def _handle_section(
        self,
        line: str,
    ) -> None:
        tokens = self._parse_kv(
            line,
            "RUSTOS_MODULE_SECTION",
        )

        if tokens is None:
            return

        try:
            module_id = int(
                tokens["id"]
            )

            name = tokens["name"]

            addr = int(
                tokens["addr"],
                16,
            )

            size = int(
                tokens["size"],
                16,
            )

        except (
            KeyError,
            ValueError,
        ) as exc:
            self._print(
                "[rustos-meta] "
                "WARNING: bad MODULE_SECTION "
                f"({exc!r}): {line!r}"
            )

            return

        pending = self._pending.get(
            module_id
        )

        if pending is None:
            return

        pending.sections.append(
            _Section(
                name,
                addr,
                size,
            )
        )

    def _handle_end(
        self,
        line: str,
    ) -> None:
        tokens = self._parse_kv(
            line,
            "RUSTOS_MODULE_END",
        )

        if tokens is None:
            return

        try:
            module_id = int(
                tokens["id"]
            )

        except (
            KeyError,
            ValueError,
        ) as exc:
            self._print(
                "[rustos-meta] "
                "WARNING: bad MODULE_END "
                f"({exc!r}): {line!r}"
            )

            return

        pending = self._pending.pop(
            module_id,
            None,
        )

        if pending is None:
            return

        key = (
            pending.name,
            pending.loaded,
        )

        if key in self._loaded:
            self._send_ready(
                pending.id
            )
            return

        abs_path = self._resolve_path(
            pending.name,
            pending.path,
        )

        if abs_path is None:
            self._print(
                "[rustos-meta] "
                "ERROR: could not locate "
                f"'{pending.name}' on host"
            )

            return

        module = _LoadedModule(
            pending.id,
            pending.name,
            abs_path,
            pending.preferred,
            pending.loaded,
            pending.sections,
        )

        if not self._synchronize_and_load(
            module
        ):
            return

        self._loaded[key] = module

    def _synchronize_and_load(
        self,
        module: _LoadedModule,
    ) -> bool:
        try:
            import lldb
        except Exception as exc:
            self._print(
                "[rustos-meta] "
                "ERROR: could not import "
                f"LLDB Python module: {exc!r}"
            )
            return False

        target = (
            self._debugger
            .GetSelectedTarget()
        )

        if not target.IsValid():
            self._print(
                "[rustos-meta] "
                "ERROR: no valid LLDB target"
            )
            return False

        process = target.GetProcess()

        if not process.IsValid():
            self._print(
                "[rustos-meta] "
                "ERROR: no valid LLDB process"
            )
            return False

        state = process.GetState()

        stopped_by_us = state in (
            lldb.eStateRunning,
            lldb.eStateStepping,
        )

        if stopped_by_us:
            stop_error = process.Stop()

            if not stop_error.Success():
                self._print(
                    "[rustos-meta] ERROR: "
                    "failed to stop target "
                    f"for '{module.name}': "
                    f"{stop_error.GetCString()}"
                )
                return False

            if process.GetState() != lldb.eStateStopped:
                self._print(
                    "[rustos-meta] ERROR: "
                    "target did not stop for "
                    f"'{module.name}'"
                )
                return False

        self._print(
            "[rustos-meta] loading "
            f"'{module.name}' at "
            f"{module.loaded:#018x} "
            f"({len(module.sections)} sections)"
        )

        if not self._load_module_in_lldb(
            module
        ):
            self._print(
                "[rustos-meta] "
                "ERROR: failed to load "
                f"symbols for '{module.name}'"
            )

            return False

        if not self._send_ready(
            module.id
        ):
            self._print(
                "[rustos-meta] "
                "ERROR: failed to acknowledge "
                f"module {module.id} "
                f"('{module.name}')"
            )

            return False

        if stopped_by_us:
            continue_error = process.Continue()

            if not continue_error.Success():
                self._print(
                    "[rustos-meta] ERROR: "
                    "failed to resume target "
                    f"after '{module.name}': "
                    f"{continue_error.GetCString()}"
                )
                return False

        return True

    def _send_ready(
        self,
        module_id: int,
    ) -> bool:
        sender = self._ready_sender

        if sender is None:
            self._print(
                "[rustos-meta] "
                "ERROR: metadata transport "
                "has no READY sender"
            )

            return False

        return sender(
            module_id
        )

    def _load_module_in_lldb(
        self,
        module: _LoadedModule,
    ) -> bool:
        try:
            import lldb
        except Exception as exc:
            self._print(
                "[rustos-meta] ERROR: "
                "could not import LLDB "
                f"Python module: {exc!r}"
            )
            return False

        with self._lldb_lock:
            target = (
                self._debugger
                .GetSelectedTarget()
            )

            module_spec = lldb.SBModuleSpec()
            module_spec.SetFileSpec(
                lldb.SBFileSpec(module.abs_path)
            )

            lldb_module = target.AddModule(
                module_spec
            )

            if not lldb_module.IsValid():
                self._print(
                    "[rustos-meta] ERROR: "
                    "LLDB rejected module "
                    f"'{module.abs_path}'"
                )
                return False

            all_loaded = True

            for section in module.sections:
                lldb_section = (
                    lldb_module.FindSection(
                        section.name
                    )
                )

                if not lldb_section.IsValid():
                    self._print(
                        "[rustos-meta] ERROR: "
                        "could not find section "
                        f"'{section.name}' in "
                        f"'{module.name}'"
                    )
                    all_loaded = False
                    continue

                error = (
                    target.SetSectionLoadAddress(
                        lldb_section,
                        section.addr,
                    )
                )

                if not error.Success():
                    self._print(
                        "[rustos-meta] ERROR: "
                        "could not load section "
                        f"'{section.name}' for "
                        f"'{module.name}': "
                        f"{error.GetCString()}"
                    )
                    all_loaded = False

            return all_loaded

    def _resolve_path(
        self,
        name: str,
        kernel_path: str,
    ) -> Optional[str]:
        kernel_basename = (
            os.path.basename(
                kernel_path.replace(
                    "\\",
                    "/",
                )
            )
            if kernel_path
            else name
        )

        for candidate_name in (
            kernel_basename,
            name,
        ):
            candidate = os.path.abspath(
                os.path.join(
                    self._driver_dir,
                    candidate_name,
                )
            )

            if os.path.isfile(
                candidate
            ):
                return candidate.replace(
                    "\\",
                    "/",
                )

        try:
            for entry in os.scandir(
                self._driver_dir
            ):
                if (
                    entry.is_file()
                    and entry.name.lower()
                    == name.lower()
                ):
                    return (
                        os.path.abspath(
                            entry.path
                        )
                        .replace(
                            "\\",
                            "/",
                        )
                    )

        except OSError:
            pass

        return None

    @staticmethod
    def _parse_kv(
        line: str,
        prefix: str,
    ) -> Optional[
        Dict[str, str]
    ]:
        rest = line[
            len(prefix):
        ].strip()

        try:
            parts = shlex.split(
                rest
            )

        except ValueError:
            return None

        result: Dict[
            str,
            str,
        ] = {}

        for part in parts:
            if "=" not in part:
                continue

            key, _, value = (
                part.partition("=")
            )

            result[key] = value

        return result

    def _print(
        self,
        message: str,
    ) -> None:
        _write_codelldb_console(
            self._debugger,
            message + "\n",
        )


class _SerialConnection:
    def __init__(
        self,
        debugger,
        host: str,
        port: int,
    ) -> None:
        self._debugger = debugger
        self._host = host
        self._port = port

        self._sock: Optional[
            socket.socket
        ] = None

        self._stop = threading.Event()

        self._thread: Optional[
            threading.Thread
        ] = None

        self._hello_thread: Optional[
            threading.Thread
        ] = None

        self._send_lock = threading.Lock()
        self._mux_lock = threading.Lock()

        self._buf = bytearray()

        self._meta: Optional[
            _MetaProtocol
        ] = None

    def start(self) -> bool:
        try:
            sock = socket.create_connection(
                (
                    self._host,
                    self._port,
                ),
                timeout=5.0,
            )

            sock.settimeout(
                None
            )

            self._sock = sock

        except OSError as exc:
            _write_codelldb_console(
                self._debugger,
                "[rustos-serial] ERROR: "
                "could not connect to "
                f"{self._host}:"
                f"{self._port}: {exc}\n",
            )

            return False

        self._thread = threading.Thread(
            target=self._reader_loop,
            name="rustos-serial-reader",
            daemon=True,
        )

        self._thread.start()

        self._hello_thread = (
            threading.Thread(
                target=self._hello_loop,
                name="rustos-meta-uart0-hello",
                daemon=True,
            )
        )

        self._hello_thread.start()

        _write_codelldb_console(
            self._debugger,
            "[rustos-serial] connected to "
            f"{self._host}:"
            f"{self._port}\n",
        )

        return True

    def stop(self) -> None:
        self._stop.set()

        sock = self._sock
        self._sock = None

        if sock is not None:
            try:
                sock.shutdown(
                    socket.SHUT_RDWR
                )
            except OSError:
                pass

            try:
                sock.close()
            except OSError:
                pass

        for thread in (
            self._thread,
            self._hello_thread,
        ):
            if (
                thread is not None
                and thread
                is not threading.current_thread()
            ):
                thread.join(
                    timeout=2.0
                )

        self._thread = None
        self._hello_thread = None

    def attach_metadata(
        self,
        protocol: _MetaProtocol,
    ) -> None:
        with self._mux_lock:
            self._meta = protocol

        self._send(
            META_MUX_HELLO
        )

    def detach_metadata(
        self,
    ) -> None:
        with self._mux_lock:
            self._meta = None

    def send_module_ready(
        self,
        module_id: int,
    ) -> bool:
        return self._send(
            META_PREFIX
            + (
                "RUSTOS_MODULE_READY "
                f"id={module_id}\n"
            ).encode("ascii")
        )

    def _send(
        self,
        data: bytes,
    ) -> bool:
        sock = self._sock

        if sock is None:
            return False

        try:
            with self._send_lock:
                sock.sendall(
                    data
                )

            return True

        except OSError:
            return False

    def _hello_loop(self) -> None:
        while not self._stop.wait(
            HELLO_RETRY_SECONDS
        ):
            with self._mux_lock:
                protocol = self._meta

            if (
                protocol is None
                or protocol.hello_acked
            ):
                continue

            if not self._send(
                META_MUX_HELLO
            ):
                return

    def _reader_loop(self) -> None:
        while not self._stop.is_set():
            sock = self._sock

            if sock is None:
                return

            try:
                chunk = sock.recv(
                    4096
                )

            except OSError:
                return

            if not chunk:
                self._flush_console()
                return

            self._consume(
                chunk
            )

    def _consume(
        self,
        chunk: bytes,
    ) -> None:
        console_chunks: List[
            bytes
        ] = []

        metadata_lines: List[
            bytes
        ] = []

        with self._mux_lock:
            self._buf.extend(
                chunk
            )

            while self._buf:
                prefix_index = (
                    self._buf.find(
                        META_PREFIX
                    )
                )

                if prefix_index < 0:
                    keep = (
                        self
                        ._prefix_suffix_length()
                    )

                    emit_len = (
                        len(self._buf)
                        - keep
                    )

                    if emit_len:
                        console_chunks.append(
                            bytes(
                                self._buf[
                                    :emit_len
                                ]
                            )
                        )

                        del self._buf[
                            :emit_len
                        ]

                    break

                if prefix_index > 0:
                    console_chunks.append(
                        bytes(
                            self._buf[
                                :prefix_index
                            ]
                        )
                    )

                    del self._buf[
                        :prefix_index
                    ]

                newline = self._buf.find(
                    b"\n",
                    len(META_PREFIX),
                )

                if newline < 0:
                    break

                metadata_lines.append(
                    bytes(
                        self._buf[
                            len(META_PREFIX):
                            newline
                        ]
                    ).rstrip(
                        b"\r"
                    )
                )

                del self._buf[
                    : newline + 1
                ]

            protocol = self._meta

        for data in console_chunks:
            _write_codelldb_console(
                self._debugger,
                data.decode(
                    "utf-8",
                    errors="replace",
                ),
            )

        if protocol is not None:
            for line in metadata_lines:
                protocol.process_line_bytes(
                    line
                )

    def _prefix_suffix_length(
        self,
    ) -> int:
        max_len = min(
            len(self._buf),
            len(META_PREFIX) - 1,
        )

        for length in range(
            max_len,
            0,
            -1,
        ):
            if (
                self._buf[-length:]
                == META_PREFIX[:length]
            ):
                return length

        return 0

    def _flush_console(
        self,
    ) -> None:
        with self._mux_lock:
            remaining = bytes(
                self._buf
            )

            self._buf.clear()

        if remaining:
            _write_codelldb_console(
                self._debugger,
                remaining.decode(
                    "utf-8",
                    errors="replace",
                ),
            )


_active_protocol: Optional[
    _MetaProtocol
] = None

_active_serial: Optional[
    _SerialConnection
] = None


class _RustosSerialConnectCommand:
    def __init__(
        self,
        debugger,
        _internal_dict,
    ) -> None:
        pass

    def __call__(
        self,
        debugger,
        command: str,
        exe_ctx,
        result,
    ) -> None:
        global _active_serial

        args = shlex.split(
            command
        )

        if len(args) != 2:
            result.SetError(
                "usage: "
                "rustos-serial-connect "
                "HOST PORT"
            )

            return

        host, port_text = args

        try:
            port = int(
                port_text
            )

        except ValueError:
            result.SetError(
                f"invalid port: {port_text!r}"
            )

            return

        if _active_serial is not None:
            _active_serial.stop()

        connection = _SerialConnection(
            debugger,
            host,
            port,
        )

        if not connection.start():
            result.SetError(
                "failed to connect to "
                f"{host}:{port}"
            )

            return

        _active_serial = connection

        if _active_protocol is not None:
            _active_protocol.set_ready_sender(
                connection.send_module_ready
            )

            connection.attach_metadata(
                _active_protocol
            )

        result.SetStatus(0)

    def get_short_help(
        self,
    ) -> str:
        return (
            "Connect to the RustOS "
            "primary serial socket"
        )

    def get_long_help(
        self,
    ) -> str:
        return (
            "rustos-serial-connect "
            "HOST PORT"
        )


class _RustosMetaConnectCommand:
    def __init__(
        self,
        debugger,
        _internal_dict,
    ) -> None:
        pass

    def __call__(
        self,
        debugger,
        command: str,
        exe_ctx,
        result,
    ) -> None:
        global _active_protocol

        args = shlex.split(
            command
        )

        if len(args) != 1:
            result.SetError(
                "usage: "
                "rustos-meta-connect "
                "DRIVER_DIR"
            )

            return

        if _active_serial is None:
            result.SetError(
                "rustos-serial-connect "
                "must run first"
            )
            return

        _active_serial.detach_metadata()

        protocol = _MetaProtocol(
            debugger,
            args[0],
        )

        _active_protocol = protocol

        protocol.set_ready_sender(
            _active_serial.send_module_ready
        )

        _active_serial.attach_metadata(
            protocol
        )

        _write_codelldb_console(
            debugger,
            "[rustos-meta] attached "
            "to primary serial, "
            "driver dir: "
            f"{protocol.driver_dir}\n",
        )

        result.SetStatus(0)

    def get_short_help(
        self,
    ) -> str:
        return (
            "Enable RustOS dynamic "
            "driver symbol metadata"
        )

    def get_long_help(
        self,
    ) -> str:
        return (
            "rustos-meta-connect "
            "DRIVER_DIR"
        )


def __lldb_init_module(
    debugger,
    internal_dict,
) -> None:
    debugger.HandleCommand(
        "command script add "
        "-c "
        "rustos_meta."
        "_RustosSerialConnectCommand "
        "rustos-serial-connect"
    )

    debugger.HandleCommand(
        "command script add "
        "-c "
        "rustos_meta."
        "_RustosMetaConnectCommand "
        "rustos-meta-connect"
    )

    _write_codelldb_console(
        debugger,
        "[rustos-meta] loaded — use "
        "'rustos-meta-connect "
        "DRIVER_DIR' "
        "to start\n",
    )
