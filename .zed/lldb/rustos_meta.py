from __future__ import annotations

import os
import shlex
import socket
import threading
from typing import Dict, List, Optional, Tuple


class _Section:
    __slots__ = ("name", "addr", "size")

    def __init__(self, name: str, addr: int, size: int) -> None:
        self.name = name
        self.addr = addr
        self.size = size


class _PendingModule:
    __slots__ = ("id", "name", "path", "preferred", "loaded", "sections")

    def __init__(
        self, module_id: int, name: str, path: str, preferred: int, loaded: int
    ) -> None:
        self.id = module_id
        self.name = name
        self.path = path
        self.preferred = preferred
        self.loaded = loaded
        self.sections: List[_Section] = []


class _LoadedModule:
    __slots__ = ("id", "name", "abs_path", "preferred", "loaded", "sections")

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


class _MetaConnection:
    HELLO_MSG = b"RUSTOS_META_HELLO version=1\n"
    ACK_PREFIX = "RUSTOS_META_HELLO_ACK"

    def __init__(self, debugger, host: str, port: int, driver_dir: str) -> None:
        self._debugger = debugger
        self._host = host
        self._port = port
        self._driver_dir = os.path.abspath(driver_dir).replace("\\", "/")
        self._loaded: Dict[Tuple[str, int], _LoadedModule] = {}
        self._pending: Dict[int, _PendingModule] = {}
        self._queue: List[_LoadedModule] = []
        self._queue_lock = threading.Lock()
        self._lldb_lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        try:
            self._sock = socket.create_connection((self._host, self._port), timeout=5.0)
            self._sock.settimeout(None)
            self._sock.sendall(self.HELLO_MSG)
        except OSError as exc:
            self._print(
                f"[rustos-meta] ERROR: could not connect to {self._host}:{self._port}: {exc}"
            )
            return False

        self._thread = threading.Thread(
            target=self._reader_loop, name="rustos-meta-reader", daemon=True
        )
        self._thread.start()
        self._print(
            f"[rustos-meta] connected to {self._host}:{self._port}, driver dir: {self._driver_dir}"
        )
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)

    def _reader_loop(self) -> None:
        buf = b""
        while not self._stop.is_set():
            try:
                chunk = self._sock.recv(4096)
            except OSError:
                if not self._stop.is_set():
                    self._print("[rustos-meta] socket closed")
                break
            if not chunk:
                if not self._stop.is_set():
                    self._print("[rustos-meta] EOF on metadata socket")
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    self._process_line(
                        line.rstrip(b"\r").decode("utf-8", errors="replace")
                    )
                except Exception as exc:
                    self._print(f"[rustos-meta] WARNING: {exc!r}")

    def _process_line(self, line: str) -> None:
        if not line:
            return
        if line.startswith(self.ACK_PREFIX):
            self._print("[rustos-meta] kernel acknowledged hello — snapshot incoming")
        elif line.startswith("RUSTOS_MODULE_BEGIN"):
            self._handle_begin(line)
        elif line.startswith("RUSTOS_MODULE_SECTION"):
            self._handle_section(line)
        elif line.startswith("RUSTOS_MODULE_END"):
            self._handle_end(line)

    def _handle_begin(self, line: str) -> None:
        tokens = self._parse_kv(line, "RUSTOS_MODULE_BEGIN")
        if tokens is None:
            return
        try:
            module_id = int(tokens["id"])
            name = tokens["name"]
            path = tokens.get("path", "")
            preferred = int(tokens["preferred"], 16)
            loaded = int(tokens["loaded"], 16)
        except (KeyError, ValueError) as exc:
            self._print(f"[rustos-meta] WARNING: bad MODULE_BEGIN ({exc!r}): {line!r}")
            return
        self._pending[module_id] = _PendingModule(
            module_id, name, path, preferred, loaded
        )

    def _handle_section(self, line: str) -> None:
        tokens = self._parse_kv(line, "RUSTOS_MODULE_SECTION")
        if tokens is None:
            return
        try:
            module_id = int(tokens["id"])
            name = tokens["name"]
            addr = int(tokens["addr"], 16)
            size = int(tokens["size"], 16)
        except (KeyError, ValueError) as exc:
            self._print(
                f"[rustos-meta] WARNING: bad MODULE_SECTION ({exc!r}): {line!r}"
            )
            return
        pending = self._pending.get(module_id)
        if pending is None:
            return
        pending.sections.append(_Section(name, addr, size))

    def _handle_end(self, line: str) -> None:
        tokens = self._parse_kv(line, "RUSTOS_MODULE_END")
        if tokens is None:
            return
        try:
            module_id = int(tokens["id"])
        except (KeyError, ValueError) as exc:
            self._print(f"[rustos-meta] WARNING: bad MODULE_END ({exc!r}): {line!r}")
            return
        pending = self._pending.pop(module_id, None)
        if pending is None:
            return

        key = (pending.name, pending.loaded)
        if key in self._loaded:
            return

        abs_path = self._resolve_path(pending.name, pending.path)
        if abs_path is None:
            self._print(
                f"[rustos-meta] WARNING: could not locate '{pending.name}' on host — skipping"
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
        self._loaded[key] = module

        with self._queue_lock:
            self._queue.append(module)
        self._flush_queue()

    def _flush_queue(self) -> None:
        with self._queue_lock:
            items = list(self._queue)
            self._queue.clear()
        for module in items:
            self._load_module_in_lldb(module)

    def _load_module_in_lldb(self, module: _LoadedModule) -> None:
        with self._lldb_lock:
            self._print(
                f"[rustos-meta] loading '{module.name}' at {module.loaded:#018x} ({len(module.sections)} sections)"
            )
            self._run_lldb(f'target modules add "{module.abs_path}"')

            if module.sections:
                section_args = " ".join(
                    f"{s.name} {s.addr:#x}" for s in module.sections
                )
                result = self._run_lldb(
                    f'target modules load --file "{module.abs_path}" {section_args}'
                )
                if result is not None and result.GetError():
                    for s in module.sections:
                        self._run_lldb(
                            f'target modules load --file "{module.abs_path}" {s.name} {s.addr:#x}'
                        )

    def _run_lldb(self, cmd: str):
        try:
            interp = self._debugger.GetCommandInterpreter()
            import lldb

            result = lldb.SBCommandReturnObject()
            interp.HandleCommand(cmd, result)
            if not result.Succeeded():
                self._print(
                    f"[rustos-meta] LLDB error for `{cmd}`: {result.GetError()}"
                )
            return result
        except Exception as exc:
            self._print(f"[rustos-meta] exception running `{cmd}`: {exc!r}")
            return None

    def _resolve_path(self, name: str, kernel_path: str) -> Optional[str]:
        kernel_basename = (
            os.path.basename(kernel_path.replace("\\", "/")) if kernel_path else name
        )

        for candidate_name in (kernel_basename, name):
            candidate = os.path.abspath(os.path.join(self._driver_dir, candidate_name))
            if os.path.isfile(candidate):
                return candidate.replace("\\", "/")

        try:
            for entry in os.scandir(self._driver_dir):
                if entry.is_file() and entry.name.lower() == name.lower():
                    return os.path.abspath(entry.path).replace("\\", "/")
        except OSError:
            pass

        return None

    @staticmethod
    def _parse_kv(line: str, prefix: str) -> Optional[Dict[str, str]]:
        rest = line[len(prefix) :].strip()
        try:
            parts = shlex.split(rest)
        except ValueError:
            return None
        result: Dict[str, str] = {}
        for part in parts:
            if "=" in part:
                k, _, v = part.partition("=")
                result[k] = v
        return result

    def _print(self, msg: str) -> None:
        print(msg)


_active_connection: Optional[_MetaConnection] = None


class _RustosMetaConnectCommand:
    def __init__(self, debugger, _internal_dict) -> None:
        pass

    def __call__(self, debugger, command: str, exe_ctx, result) -> None:
        global _active_connection

        args = shlex.split(command)
        if len(args) != 3:
            result.SetError("usage: rustos-meta-connect HOST PORT DRIVER_DIR")
            return

        host, port_str, driver_dir = args
        try:
            port = int(port_str)
        except ValueError:
            result.SetError(f"invalid port: {port_str!r}")
            return

        if _active_connection is not None:
            _active_connection.stop()

        conn = _MetaConnection(debugger, host, port, driver_dir)
        if not conn.start():
            result.SetError(f"failed to connect to {host}:{port}")
            return

        _active_connection = conn
        result.SetStatus(0)

    def get_short_help(self) -> str:
        return (
            "Connect to RustOS COM2 metadata socket for dynamic driver symbol loading"
        )

    def get_long_help(self) -> str:
        return (
            "rustos-meta-connect HOST PORT DRIVER_DIR\n\n"
            "  HOST        metadata socket address (usually 127.0.0.1)\n"
            "  PORT        TCP port (default 4322)\n"
            "  DRIVER_DIR  host path to driver build output directory\n"
        )


def __lldb_init_module(debugger, internal_dict) -> None:
    debugger.HandleCommand(
        "command script add -c rustos_meta._RustosMetaConnectCommand rustos-meta-connect"
    )
    print(
        "[rustos-meta] loaded — use 'rustos-meta-connect HOST PORT DRIVER_DIR' to start"
    )
