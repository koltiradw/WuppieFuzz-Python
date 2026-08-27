from __future__ import annotations

import os
import struct

MAGIC = b"WGCA"
VERSION = 0x01
REQUEST_DUMP = 0x01
RESPONSE_DUMP = 0x02
HEADER_FMT = "<4sBBI"  # magic(4) version(1) type(1) length(4 LE)
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def _frame(msg_type: int, payload: bytes) -> bytes:
    return struct.pack(HEADER_FMT, MAGIC, VERSION, msg_type, len(payload)) + payload


def build_request_dump(reset_flag: int) -> bytes:
    return _frame(REQUEST_DUMP, bytes([reset_flag & 0xFF]))


def build_response_dump(cov_map: bytes) -> bytes:
    return _frame(RESPONSE_DUMP, cov_map)


def parse_header(header: bytes) -> tuple[int, int, int]:
    magic, version, msg_type, length = struct.unpack(HEADER_FMT, header)
    if magic != MAGIC:
        raise ValueError(f"Invalid magic (got {magic!r}, expected {MAGIC!r})")
    return version, msg_type, length


def _normalize_prefix(path: str) -> str:
    return os.path.abspath(path).rstrip(os.sep)


def is_included(filename: str, include_prefixes: list[str]) -> bool:
    if not include_prefixes:
        return True
    norm = os.path.abspath(filename)
    prefixes = [_normalize_prefix(p) for p in include_prefixes]
    return any(norm == p or norm.startswith(p + os.sep) for p in prefixes)


if os.environ.get("COVERAGE_PROCESS_START"):
    print("WuppieFuzz - Python code coverage monitor is booting..")

    import sys
    import socket
    import threading
    import traceback
    from types import CodeType
    from typing import Any

    class CovMap:
        def __init__(self, size: int) -> None:
            self._data = bytearray(size)
            self._size = size

        def data(self) -> bytearray:
            return self._data

        def clear(self) -> None:
            self._data = bytearray(self._size)

        def copy_and_reset(self, do_reset: bool) -> bytes:
            old = self._data
            if do_reset:
                self.clear()
            return bytes(old)

        def __getitem__(self, index: int) -> int:
            return self._data[index % self._size]

        def __setitem__(self, index: int, value: int) -> None:
            if value > 255:
                value = 255
            self._data[index % self._size] = value

        def __len__(self) -> int:
            return self._size

        def __repr__(self) -> str:
            return repr(self._data)

    MAP_SIZE = int(os.environ.get("WUPPIE_COVMAP_SIZE", 65536))
    afl_map = CovMap(MAP_SIZE)
    prev_location = 0

    include_prefixes = [
        _normalize_prefix(p)
        for p in os.environ.get("WUPPIE_COVERAGE_INCLUDE", "").split(os.pathsep)
        if p
    ]
    _keep_cache: dict[CodeType, bool] = {}

    def cond_callback(
        code: CodeType, instruction_offset: int, next_instruction_offset: int
    ) -> None:
        global prev_location, afl_map
        keep = _keep_cache.get(code)
        if keep is None:
            keep = is_included(code.co_filename, include_prefixes)
            _keep_cache[code] = keep
        if not keep:
            return
        afl_map[(prev_location ^ next_instruction_offset)] += 1
        prev_location = next_instruction_offset // 2

    if sys.version_info < (3, 12):
        print("WuppieFuzz - sys.monitoring requires Python 3.12+, exiting.")
        from sys import exit

        exit(1)

    events = sys.monitoring.events
    tool_id = sys.monitoring.COVERAGE_ID
    sys.monitoring.use_tool_id(tool_id, "cov_tracker")
    sys.monitoring.register_callback(tool_id, events.JUMP, cond_callback)
    if sys.version_info >= (3, 14):
        branch_events = events.BRANCH_LEFT | events.BRANCH_RIGHT
        sys.monitoring.register_callback(tool_id, events.BRANCH_LEFT, cond_callback)
        sys.monitoring.register_callback(tool_id, events.BRANCH_RIGHT, cond_callback)
    else:
        branch_events = events.BRANCH
        sys.monitoring.register_callback(tool_id, events.BRANCH, cond_callback)
    sys.monitoring.set_events(tool_id, branch_events | events.JUMP)

    DEBUG = False
    if os.environ.get("WUPPIE_DEBUG_PYTHON"):
        DEBUG = True
        print("Enabled debug information")

    PORT = int(os.environ.get("WUPPIE_COVERAGE_PORT", 1337))

    if DEBUG:
        if include_prefixes:
            print(f"WuppieFuzz - Coverage filter includes: {include_prefixes}")
        else:
            print("WuppieFuzz - No coverage filter set; all code counted")

    class CovAgentSocket(socket.socket):
        @staticmethod
        def receive(nb_bytes: int, conn: socket.socket) -> bytearray:
            received = bytearray()
            while len(received) < nb_bytes:
                new_bytes = conn.recv(nb_bytes - len(received))
                if not new_bytes:
                    print("WuppieFuzz - TCP Client disconnected while receiving bytes")
                    raise BrokenPipeError("Client probably disconnected")
                received += new_bytes
            return received

        def send(self, connection: socket.socket, *args: Any, **kwargs: Any) -> None:
            try:
                connection.sendall(*args, **kwargs)
            except Exception as excep:
                print("WuppieFuzz - TCP Client disconnected while sending bytes")
                raise excep

        def start(self) -> None:
            try:
                self.start_listening()
            except Exception:
                traceback.print_exc()

        def start_listening(self) -> None:
            print("Wuppiefuzz - Started listening", flush=True)
            while True:
                connection, address = self.accept()
                print(
                    f"WuppieFuzz - Incoming TCP connection from {address}", flush=True
                )
                try:
                    while True:
                        header = self.receive(HEADER_SIZE, connection)
                        _version, msg_type, length = parse_header(header)
                        payload = self.receive(length, connection)
                        if msg_type == REQUEST_DUMP:
                            reset_flag = payload[0]
                            cov = afl_map.copy_and_reset(reset_flag)
                            self.send(connection, build_response_dump(cov))
                            if DEBUG:
                                print(
                                    f"WuppieFuzz - Sent {len(cov)} bytes in cov_map dump",
                                    flush=True,
                                )
                        else:
                            print(
                                f"WuppieFuzz - Unknown message type {msg_type:#x}, closing connection",
                                flush=True,
                            )
                            break
                except Exception as e:
                    print(f"Received exception {e}", flush=True)
                finally:
                    try:
                        connection.close()
                    except Exception:
                        pass
                    print(
                        "WuppieFuzz - TCP connection lost, waiting for reconnect",
                        flush=True,
                    )

    agent_sock = CovAgentSocket(socket.AF_INET, socket.SOCK_STREAM)
    agent_sock.bind(("0.0.0.0", PORT))
    agent_sock.listen(1)
    thread = threading.Thread(target=agent_sock.start)
    thread.daemon = True
    try:
        thread.start()
    except Exception as e:
        print(e)

    print(
        f"WuppieFuzz - Started code coverage monitor TCP server in background (port {PORT})"
    )
