"""Smoke tests for sysmon (standard library only).

    python3 -m unittest discover -s tests -v
"""

import fcntl
import importlib.machinery
import importlib.util
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "sysmon")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def load_module():
    loader = importlib.machinery.SourceFileLoader("sysmon_mod", SCRIPT)
    spec = importlib.util.spec_from_loader("sysmon_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def run(*args, env=None):
    e = dict(os.environ, LANG="C.UTF-8", **(env or {}))
    return subprocess.run([SCRIPT] + list(args), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=e, timeout=30)


class OnceMode(unittest.TestCase):
    def check_widths(self, out, width):
        mod = load_module()
        for line in out.decode("utf-8").splitlines():
            self.assertEqual(mod.text_width(ANSI.sub("", line)), width, repr(line))

    def test_widths_and_colour_modes(self):
        for width in (40, 64, 80, 120, 200):
            for colors in ("16", "256", "truecolor"):
                res = run("--once", "-w", str(width), "--color", "always", "--colors", colors)
                self.assertEqual(res.returncode, 0, res.stderr.decode())
                self.assertEqual(res.stderr, b"")
                self.check_widths(res.stdout, width)

    def test_plain_output_when_piped(self):
        res = run("--once", "-w", "100")
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        self.assertNotIn(b"\x1b[", res.stdout)
        for word in (b"CPU", b"Memory", b"Network", b"Disks", b"Processes"):
            self.assertIn(word, res.stdout)

    def test_ascii(self):
        res = run("--once", "-w", "100", "--ascii")
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        res.stdout.decode("ascii")  # must be pure ASCII

    def test_sorts(self):
        for key in ("cpu", "mem", "pid", "time", "name"):
            res = run("--once", "-s", key, "-n", "5")
            self.assertEqual(res.returncode, 0, res.stderr.decode())

    def test_runs_via_sh(self):
        res = subprocess.run(["sh", SCRIPT, "--version"], stdout=subprocess.PIPE, timeout=30)
        self.assertTrue(res.stdout.startswith(b"sysmon "))


class Helpers(unittest.TestCase):
    def setUp(self):
        self.m = load_module()

    def test_fmt_bytes(self):
        f = self.m.fmt_bytes
        self.assertEqual(f(512), "512B")
        self.assertEqual(f(1536), "1.5K")
        self.assertEqual(f(16.5 * 2 ** 30), "16.5G")
        self.assertEqual(f(120 * 2 ** 30), "120G")
        for n in (0, 999, 1000, 1023, 99.96 * 2 ** 20, 10 ** 18):
            self.assertLessEqual(len(f(n)), 5, n)

    def test_cputime(self):
        hz = self.m.CLK_TCK
        self.assertEqual(self.m.fmt_cputime(int(187.45 * hz)), "3:07.45")
        self.assertEqual(self.m.fmt_cputime(int(3 * 3600 * hz)), "3h00:00")

    def test_parse_keys(self):
        k = self.m.parse_keys(b"q\x1b[A\x1b[6~\x1bx\x1b[1;5Cz\xd0\xb6")
        self.assertEqual(k, ["q", "UP", "PGDN", "ESC", "x", "z", "ж"])

    def test_sanitize_strips_escapes(self):
        self.assertNotIn("\x1b", self.m.sanitize("evil\x1b[2Jname"))

    def test_clip_wide_chars(self):
        self.assertEqual(self.m.text_width(self.m.clip("日本語のテキスト", 7)), 7)


class LiveMode(unittest.TestCase):
    def test_keys_resize_and_quit(self):
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.environ["LANG"] = "C.UTF-8"
            os.execv(SCRIPT, [SCRIPT, "-i", "0.25"])
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
        out = bytearray()

        def pump(t):
            end = time.time() + t
            while time.time() < end:
                if select.select([fd], [], [], max(0, end - time.time()))[0]:
                    try:
                        out.extend(os.read(fd, 65536))
                    except OSError:
                        return

        pump(1.5)
        for key in [b"?", b"x", b"m", b"p", b"r", b"k", b"/", b"py", b"\r", b"\x1b",
                    b"\x1b[B", b"\x1b[6~", b"\x1b[F", b"+", b"-", b" ", b" ", b"\x0c"]:
            os.write(fd, key)
            pump(0.15)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 20, 50, 0, 0))
        pump(0.5)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 8, 30, 0, 0))
        pump(0.5)
        os.write(fd, b"q")
        pump(1.0)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.WEXITSTATUS(status), 0, bytes(out[-2000:]))
        self.assertNotIn(b"Traceback", out)
        self.assertTrue(bytes(out).rstrip().endswith(b"\x1b[?1049l"))


if __name__ == "__main__":
    unittest.main()
