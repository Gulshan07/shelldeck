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

EXPECT_TIMEOUT = 30


def parse(script: str):
    steps = []
    for raw in script.splitlines():
        line = raw.rstrip("\n")
        if not line.strip() or line.strip().startswith("#"):
            continue
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
    return steps


async def run(steps, write, recent):
    """Drive a macro against a live session.

    `write(bytes)` sends input (proc.stdin.write for SSH, writer.write for
    telnet/serial); `recent` is a mutable bytearray the caller keeps filled with
    the latest terminal output, so `expect` can watch it. Yields status strings
    for the UI. Raises TimeoutError on a missed expect.
    """
    for op, arg in steps:
        if op == "send":
            write(arg.encode())
            yield f"sent: {arg.strip()[:40]}"
        elif op == "sleep":
            await asyncio.sleep(min(arg, 60))
        elif op == "expect":
            target = arg.encode()
            deadline = asyncio.get_event_loop().time() + EXPECT_TIMEOUT
            while target not in bytes(recent):
                if asyncio.get_event_loop().time() > deadline:
                    raise TimeoutError(f"expected {arg!r} but it never appeared")
                await asyncio.sleep(0.1)
            yield f"matched: {arg[:40]}"
