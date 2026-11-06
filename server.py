#!/usr/bin/env python3
"""Local web server and GDB/MI bridge for an x86 assembly debugger."""

import errno
import json
import os
import pty
import re
import select
import shutil
import subprocess
import tempfile
import threading
import time
import tty
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


HOST = "127.0.0.1"
PORT = 8000
MAX_CODE_SIZE = 256 * 1024
MAX_PROGRAM_OUTPUT = 256 * 1024
RUN_TIMEOUT_SECONDS = 120
ARCHITECTURES = {
    "i386": {
        "nasm_format": "elf",
        "linker_mode": "elf_i386",
        "registers": ("eax", "ebx", "ecx", "edx", "esp", "ebp", "esi", "edi", "eflags"),
        "pc": "eip",
        "bits": 32,
    },
    "x86_64": {
        "nasm_format": "elf64",
        "linker_mode": "elf_x86_64",
        "registers": (
            "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags",
        ),
        "pc": "rip",
        "bits": 64,
    },
}
INDEX_FILE = Path(__file__).with_name("index.html")
MI_INTEGER_PATTERN = re.compile(r"^\s*([+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))")
LINKERS = ("ld", "gcc")


def build_commands(architecture, linker):
    if architecture not in ARCHITECTURES:
        raise RuntimeError("Unsupported architecture. Choose i386 or x86_64.")
    if linker not in LINKERS:
        raise RuntimeError("Unsupported linker. Choose ld or gcc.")

    config = ARCHITECTURES[architecture]
    assemble = ["nasm", "-f", config["nasm_format"], "program.s", "-o", "program.o"]
    if linker == "ld":
        link = ["ld", "-m", config["linker_mode"], "program.o", "-o", "program"]
        entry_point = "_start"
    else:
        gcc_mode = "-m32" if config["bits"] == 32 else "-m64"
        link = ["gcc", gcc_mode, "-no-pie", "program.o", "-o", "program"]
        entry_point = "main"
    return [assemble, link], entry_point


def has_global_symbol(code, symbol):
    return re.search(
        rf"(?im)^\s*global\s+(?:[^;,\n]+,\s*)*{re.escape(symbol)}(?=\s|[:,]|$)",
        code,
    ) is not None


def parse_mi_integer(value):
    """Parse GDB's decimal/hex MI values, including signed and zero-padded decimals."""
    match = MI_INTEGER_PATTERN.match(value)
    if not match:
        raise ValueError(f"Not an integer GDB value: {value!r}")
    token = match.group(1)
    sign = -1 if token.startswith("-") else 1
    digits = token.lstrip("+-")
    base = 16 if digits.lower().startswith("0x") else 10
    return sign * int(digits, base)


def stopped_info(lines):
    line = next((line for line in lines if line.startswith("*stopped,")), "")
    reason = re.search(r'(?:^|,)reason="([^"]+)"', line)
    signal_name = re.search(r'(?:^|,)signal-name="([^"]+)"', line)
    signal_meaning = re.search(r'(?:^|,)signal-meaning="((?:\\.|[^"\\])*)"', line)
    return {
        "reason": reason.group(1) if reason else None,
        "signal_name": signal_name.group(1) if signal_name else None,
        "signal_meaning": (
            json.loads('"' + signal_meaning.group(1) + '"') if signal_meaning else None
        ),
    }


def exited_state(architecture, stop):
    state = {
        "status": "signal_exit" if stop["reason"] == "exited-signalled" else "exited",
        "architecture": architecture,
        "registers": {},
        "instructions": [],
        "pc_name": ARCHITECTURES[architecture]["pc"],
        "pc": None,
    }
    if stop["signal_name"]:
        state["signal_name"] = stop["signal_name"]
    if stop["signal_meaning"]:
        state["signal_meaning"] = stop["signal_meaning"]
    return state


class GdbSession:
    def __init__(self, executable, architecture):
        self.architecture = architecture
        self.output_master, self.output_slave = pty.openpty()
        try:
            tty.setraw(self.output_slave)
            self.process = subprocess.Popen(
                ["gdb", "-q", "--interpreter=mi", str(executable)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        except Exception:
            os.close(self.output_master)
            os.close(self.output_slave)
            raise
        self.buffer = bytearray()
        self.token = 0
        self.lock = threading.Lock()
        self.output_lock = threading.Lock()
        self.output_ready = threading.Condition(self.output_lock)
        self.output_buffer = bytearray()
        self.output_truncated = False
        self.output_reader_error = None
        self.output_stop = threading.Event()
        self.output_thread = threading.Thread(target=self._read_program_output, daemon=True)
        self.output_thread.start()

    def set_inferior_tty(self):
        tty_path = os.ttyname(self.output_slave)
        self.command(f"-inferior-tty-set {tty_path}")
        os.close(self.output_slave)
        self.output_slave = None

    def _read_program_output(self):
        while not self.output_stop.is_set():
            try:
                readable, _, _ = select.select([self.output_master], [], [], 0.1)
                if not readable:
                    continue
                chunk = os.read(self.output_master, 4096)
            except OSError as error:
                if error.errno == errno.EIO and not self.output_stop.is_set():
                    time.sleep(0.02)
                    continue
                if not self.output_stop.is_set():
                    with self.output_ready:
                        self.output_reader_error = str(error)
                        self.output_ready.notify_all()
                return
            if not chunk:
                return
            with self.output_ready:
                remaining = MAX_PROGRAM_OUTPUT - len(self.output_buffer)
                self.output_buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.output_truncated = True
                self.output_ready.notify_all()

    def program_output(self):
        with self.output_lock:
            if self.output_reader_error:
                raise RuntimeError(f"Could not capture program output: {self.output_reader_error}")
            output = bytes(self.output_buffer)
            truncated = self.output_truncated
        text = output.decode("utf-8", "replace")
        if truncated:
            text += "\n[Program output truncated after 256 KiB]"
        return text

    def _line(self, deadline):
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self.buffer[:newline]).decode("utf-8", "replace").rstrip("\r")
                del self.buffer[: newline + 1]
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for GDB.")
            readable, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not readable:
                raise TimeoutError("Timed out waiting for GDB.")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("GDB exited unexpectedly.")
            self.buffer.extend(chunk)

    def command(self, command, wait_for_stop=False, timeout=15):
        with self.lock:
            if self.process.poll() is not None:
                raise RuntimeError("The GDB session has ended. Build again to restart it.")
            self.token += 1
            token = self.token
            self.process.stdin.write(f"{token}{command}\n".encode())
            self.process.stdin.flush()
            deadline = time.monotonic() + timeout
            lines = []
            result = None
            result_pattern = re.compile(r"^" + str(token) + r"\^(done|running|error|exit)(?:,|$)")
            while result is None:
                line = self._line(deadline)
                lines.append(line)
                if result_pattern.match(line):
                    result = line
            if result.startswith(str(token) + "^error"):
                message = re.search(r'msg="((?:\\.|[^"\\])*)"', result)
                error = json.loads('"' + message.group(1) + '"') if message else result
                raise RuntimeError(error)
            if wait_for_stop and "^running" in result:
                if not any(line.startswith("*stopped,") for line in lines):
                    while True:
                        line = self._line(deadline)
                        lines.append(line)
                        if line.startswith("*stopped,"):
                            break
                with self.output_ready:
                    self.output_ready.wait(timeout=0.01)
            return lines

    def state(self):
        values = {}
        config = ARCHITECTURES[self.architecture]
        bits = config["bits"]
        for register in (*config["registers"], config["pc"]):
            if register in ("eflags", "rflags"):
                # GDB exposes the x86-64 flags register under the name EFLAGS.
                expression = "(unsigned int)$eflags"
            else:
                expression = f"${register}"
            lines = self.command(f'-data-evaluate-expression "{expression}"')
            value = re.search(r'value="([^"]+)"', "\n".join(lines))
            if not value:
                raise RuntimeError(f"GDB did not return ${register}.")
            try:
                number = parse_mi_integer(value.group(1))
            except ValueError as error:
                raise RuntimeError(f"GDB returned an invalid ${register} value.") from error
            number &= (1 << bits) - 1
            values[register] = number if bits == 32 else f"0x{number:016x}"

        pc_name = config["pc"]
        pc = int(values[pc_name], 0) if isinstance(values[pc_name], str) else values[pc_name]
        end = min(pc + 96, (1 << bits) - 1)
        lines = self.command(f"-data-disassemble -s 0x{pc:x} -e 0x{end:x} -- 0")
        text = "\n".join(lines)
        instructions = []
        for entry in re.finditer(r'\{address="([^"]+)"[^}]*?inst="((?:\\.|[^"\\])*)"', text):
            try:
                instruction = json.loads('"' + entry.group(2) + '"')
                address = int(entry.group(1), 0)
                instructions.append({
                    "address": address if bits == 32 else f"0x{address:016x}",
                    "text": instruction,
                })
            except (ValueError, json.JSONDecodeError):
                continue
        return {
            "architecture": self.architecture,
            "registers": values,
            "instructions": instructions,
            "pc_name": pc_name,
            "pc": pc if bits == 32 else f"0x{pc:016x}",
            "output": self.program_output(),
        }

    def close(self):
        try:
            if self.process.poll() is None:
                try:
                    self.command("-gdb-exit")
                except (OSError, RuntimeError, TimeoutError):
                    self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
        finally:
            self.output_stop.set()
            if self.output_slave is not None:
                os.close(self.output_slave)
                self.output_slave = None
            self.output_thread.join(timeout=1)
            os.close(self.output_master)


class Debugger:
    def __init__(self):
        self.lock = threading.RLock()
        self.directory = None
        self.gdb = None
        self.exited = False
        self.architecture = None
        self.last_state = None

    def reset(self):
        with self.lock:
            if self.gdb:
                self.gdb.close()
                self.gdb = None
            if self.directory:
                shutil.rmtree(self.directory, ignore_errors=True)
                self.directory = None
            self.exited = False
            self.architecture = None
            self.last_state = None

    def build(self, code, architecture, linker="ld"):
        with self.lock:
            return self._build(code, architecture, linker)

    def _build(self, code, architecture, linker):
        commands, entry_point = build_commands(architecture, linker)
        self.reset()
        if not has_global_symbol(code, entry_point):
            if linker == "ld":
                raise RuntimeError(
                    "GNU ld builds must export a global _start entry point. "
                    "For a C main function or calls such as printf/exit, select GCC · main + libc."
                )
            raise RuntimeError("GCC builds must export a global main entry point.")
        self.architecture = architecture
        self.directory = tempfile.mkdtemp(prefix=f"{architecture}-debug-")
        source = Path(self.directory) / "program.s"
        executable = Path(self.directory) / "program"
        source.write_text(code, encoding="utf-8")

        for command in commands:
            print(f"Running in {self.directory}: {' '.join(command)}", flush=True)
            try:
                result = subprocess.run(
                    command,
                    cwd=self.directory,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except FileNotFoundError as error:
                self.reset()
                raise RuntimeError(f"Required tool not found: {error.filename}") from error
            except subprocess.TimeoutExpired as error:
                self.reset()
                raise RuntimeError(f"Build command timed out: {' '.join(command)}") from error
            if result.returncode:
                message = (result.stderr or result.stdout).strip()
                if command[0] == "ld":
                    message += (
                        "\nGNU ld does not link the C runtime or libc. "
                        "Select GCC · main + libc for calls such as printf and exit."
                    )
                self.reset()
                raise RuntimeError(message or f"Build command failed: {' '.join(command)}")

        try:
            self.gdb = GdbSession(executable, architecture)
            self.gdb.set_inferior_tty()
            self.gdb.command("-gdb-set disassembly-flavor intel")
            self.gdb.command(f"-break-insert {entry_point}")
            lines = self.gdb.command("-exec-run", wait_for_stop=True)
            stop = stopped_info(lines)
            self.exited = stop["reason"] in ("exited-normally", "exited", "exited-signalled")
            if self.exited:
                state = exited_state(architecture, stop)
                state["output"] = self.gdb.program_output()
                self.last_state = state
                return state
            state = {"status": "paused", **self.gdb.state()}
            if stop["signal_name"]:
                state["signal_name"] = stop["signal_name"]
                state["signal_meaning"] = stop["signal_meaning"]
            self.last_state = state
            return state
        except Exception:
            self.reset()
            raise

    def step(self, over_call=False):
        with self.lock:
            if not self.gdb:
                raise RuntimeError("No active debug session. Build a program first.")
            if self.exited:
                config = ARCHITECTURES[self.architecture]
                return {
                    "status": "exited", "architecture": self.architecture, "registers": {},
                    "instructions": [], "pc_name": config["pc"], "pc": None,
                    "output": self.gdb.program_output(),
                }
            current_instruction = None
            next_address = None
            if over_call and self.last_state:
                pc = self.last_state["pc"]
                pc = int(pc, 0) if isinstance(pc, str) else pc
                instructions = self.last_state["instructions"]
                for index, instruction in enumerate(instructions):
                    address = instruction["address"]
                    address = int(address, 0) if isinstance(address, str) else address
                    if address == pc:
                        current_instruction = instruction["text"]
                        if index + 1 < len(instructions):
                            next_address = instructions[index + 1]["address"]
                            next_address = (
                                int(next_address, 0) if isinstance(next_address, str) else next_address
                            )
                        break
            is_call = current_instruction is not None and re.match(
                r"^\s*call(?:[a-z]*)\s", current_instruction, re.IGNORECASE
            )
            if is_call and next_address is not None:
                self.gdb.command(f"-break-insert -t *0x{next_address:x}")
                lines = self.gdb.command("-exec-continue", wait_for_stop=True)
            else:
                lines = self.gdb.command("-exec-step-instruction", wait_for_stop=True)
            stop = stopped_info(lines)
            self.exited = stop["reason"] in ("exited-normally", "exited", "exited-signalled")
            if self.exited:
                state = exited_state(self.architecture, stop)
                state["output"] = self.gdb.program_output()
                self.last_state = state
                return state
            state = {"status": "paused", **self.gdb.state()}
            if stop["signal_name"]:
                state["signal_name"] = stop["signal_name"]
                state["signal_meaning"] = stop["signal_meaning"]
            self.last_state = state
            return state

    def run(self):
        with self.lock:
            if not self.gdb:
                raise RuntimeError("No active debug session. Build a program first.")
            if self.exited:
                return self.last_state
            try:
                lines = self.gdb.command(
                    "-exec-continue",
                    wait_for_stop=True,
                    timeout=RUN_TIMEOUT_SECONDS,
                )
            except TimeoutError as error:
                self.reset()
                raise RuntimeError(
                    f"Program did not stop within {RUN_TIMEOUT_SECONDS} seconds; debugger session was reset."
                ) from error
            stop = stopped_info(lines)
            self.exited = stop["reason"] in ("exited-normally", "exited", "exited-signalled")
            if self.exited:
                state = exited_state(self.architecture, stop)
                state["output"] = self.gdb.program_output()
                self.last_state = state
                return state
            state = {"status": "paused", **self.gdb.state()}
            if stop["signal_name"]:
                state["signal_name"] = stop["signal_name"]
                state["signal_meaning"] = stop["signal_meaning"]
            self.last_state = state
            return state


debugger = Debugger()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def _json(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self._json(404, {"error": "Not found"})
            return
        try:
            page = INDEX_FILE.read_bytes()
        except OSError as error:
            self._json(500, {"error": f"Could not read index.html: {error}"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        if self.path not in ("/api/build", "/api/step", "/api/step-over", "/api/run", "/api/reset"):
            self._json(404, {"error": "Not found"})
            return
        try:
            if self.path == "/api/build":
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_CODE_SIZE:
                    self._json(413, {"error": "Assembly source must be between 1 byte and 256 KiB."})
                    return
                body = json.loads(self.rfile.read(length))
                code = body.get("code") if isinstance(body, dict) else None
                architecture = body.get("architecture", "i386") if isinstance(body, dict) else None
                linker = body.get("linker", "ld") if isinstance(body, dict) else None
                if not isinstance(code, str) or not code.strip():
                    self._json(400, {"error": "Provide non-empty assembly source in the 'code' field."})
                    return
                if not isinstance(architecture, str):
                    self._json(400, {"error": "Architecture must be 'i386' or 'x86_64'."})
                    return
                if not isinstance(linker, str):
                    self._json(400, {"error": "Linker must be 'ld' or 'gcc'."})
                    return
                state = debugger.build(code, architecture, linker)
            elif self.path in ("/api/step", "/api/step-over"):
                state = debugger.step(over_call=self.path == "/api/step-over")
            elif self.path == "/api/run":
                state = debugger.run()
            else:
                debugger.reset()
                state = {"status": "ready", "registers": {}, "instructions": [], "pc_name": None, "pc": None}
            self._json(200, state)
        except (RuntimeError, TimeoutError, ValueError, json.JSONDecodeError) as error:
            self._json(400, {"error": str(error)})
        except Exception as error:
            self._json(500, {"error": f"Unexpected server error: {error}"})


if __name__ == "__main__":
    print(f"x86 visual debugger: http://{HOST}:{PORT}")
    try:
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        debugger.reset()
