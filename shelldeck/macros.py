"""Expect/send macros: a tiny script run against a live shell.

Each line is one step:
    send <text>       type text and press Enter
    send! <text>      type text with no Enter (for a prompt that wants a keypress)
    expect <substr>   wait until <substr> appears in the output (up to a timeout)
    sleep <seconds>   pause
Anything else is treated as `send`. Blank lines and #-comments are skipped.

Macro bodies live in the vault because they routinely hold a sudo password.
"""
import asyncio
import re

EXPECT_TIMEOUT = 30

# The status line is shown in the terminal, so a reply to anything that looks
# like a secret prompt is masked there. It is still typed into the shell as is.
_SECRET_PROMPT = re.compile(rb"pass(word|phrase|code)?|secret|token|\bpin\b|otp", re.I)


# A run of 2+ spaces right before a keyword means two steps got merged onto one
# line (a common paste-from-terminal artifact); split them back apart.
_MERGE = re.compile(r"\s{2,}(?=(?:send!?|expect|sleep)\s)")


def parse(script: str):
    steps = []
    for raw in script.splitlines():
        for line in _MERGE.split(raw):
            line = line.strip()            # indentation is fine; steps aren't column-sensitive
            if not line or line.startswith("#"):
                continue
            _parse_step(line, steps)
    return steps


def _parse_step(line, steps):
    if True:
        head, _, rest = line.partition(" ")
        op = head.lower()
        if op == "send":
            steps.append(("send", rest + "\n"))
        elif op == "send!":
            steps.append(("send", rest))
        elif op == "expect":
            steps.append(("expect", rest))
        elif op == "sleep":
            try:
                steps.append(("sleep", float(rest)))
            except ValueError:
                steps.append(("send", line + "\n"))
        else:
            steps.append(("send", line + "\n"))


async def run(steps, write, recent):
    """Drive a macro against a live session.

    `write(bytes)` sends input (proc.stdin.write for SSH, writer.write for
    telnet/serial); `recent` is a mutable bytearray the caller keeps filled with
    the latest terminal output, so `expect` can watch it. Yields status strings
    for the UI. Raises TimeoutError on a missed expect.
    """
    last_expect, before = "", None
    for op, arg in steps:
        if op == "send":
            tail = bytes(recent[-200:])
            fresh = tail if tail != before else b""     # only output since our last send
            secret = _SECRET_PROMPT.search(last_expect.encode() + b" " + fresh)
            write(arg.encode())
            last_expect, before = "", tail
            yield "sent: ••••••" if secret else f"sent: {arg.strip()[:40]}"
        elif op == "sleep":
            await asyncio.sleep(min(arg, 60))
        elif op == "expect":
            # Try regex first (so [#$], \\$\\s*$, etc. work like Ásbrú); if the
            # pattern isn't valid regex, fall back to a literal substring match.
            try:
                rx = re.compile(arg.encode())
                matches = lambda buf: rx.search(buf) is not None
            except re.error:
                needle = arg.encode()
                matches = lambda buf: needle in buf
            deadline = asyncio.get_event_loop().time() + EXPECT_TIMEOUT
            while not matches(bytes(recent)):
                if asyncio.get_event_loop().time() > deadline:
                    raise TimeoutError(f"expected {arg!r} but it never appeared")
                await asyncio.sleep(0.1)
            last_expect = arg
            yield f"matched: {arg[:40]}"
