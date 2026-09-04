# Contributing

Thanks for looking. Issues and pull requests are both welcome.

**`main` takes pull requests only.** Nobody pushes to it directly, including
me. Every change lands as a reviewed PR.

## The fork workflow

You do not need write access to this repository, and you will not be given it.
You work on a copy under your own account and ask me to pull from it.

```bash
# 1. Fork: press "Fork" on https://github.com/Gulshan07/EazyConnector
#    You now own https://github.com/<you>/EazyConnector

# 2. Clone YOUR fork, not mine
git clone https://github.com/<you>/EazyConnector.git
cd EazyConnector

# 3. Point "upstream" at mine, so you can pull in my later changes
git remote add upstream https://github.com/Gulshan07/EazyConnector.git
git remote -v

# 4. Branch. Never work on main -- it makes syncing painful later.
git checkout -b fix-sftp-upload-stall

# 5. Set up and make your change
python3 -m venv .venv
.venv/bin/pip install -e ".[import,serial,test]"

# 6. Run the suites (see below). They must pass.
# 7. Commit and push to YOUR fork
git commit -am "SFTP: stop the upload stalling on files over 2 GB"
git push origin fix-sftp-upload-stall
```

GitHub then shows a "Compare & pull request" button on your fork. Press it,
target `Gulshan07/EazyConnector` `main`, describe what you changed and why.

To pick up my changes later:

```bash
git checkout main
git pull upstream main
git push origin main          # keep your fork's main in sync
git checkout -b my-next-thing
```

If review asks for changes, commit onto the same branch and push again — the
PR updates itself. Don't open a second one.

## Before you open a PR

All seven suites must pass. They are plain scripts, no framework:

```bash
.venv/bin/python test_p0.py       # vault crypto, file modes, TOTP vectors, parsers
.venv/bin/python test_e2e.py      # full stack against an in-process sshd
.venv/bin/python test_live.py     # real uvicorn + WebSocket + SFTP + import/export
.venv/bin/python test_vpn.py      # the whole OpenVPN conversation (no root needed)
.venv/bin/python test_raw.py      # telnet + serial
.venv/bin/python test_sudokey.py  # reading a root-owned key via sudo
.venv/bin/python test_ui.py       # browser checks over Chrome DevTools Protocol
```

Run them directly rather than piping through `tail`, which hides output if one
hangs.

**New behaviour needs a test.** Not a suite — one assertion that fails if the
thing breaks. Several bugs here were invisible until a test double was made
*stricter than the real server*, so if you touch the SSH, SFTP, VPN or
WebSocket paths, exercise the real transport rather than a mock.

## Things that will get a PR sent back

This is a security tool for a shared, multi-user machine. These are not
negotiable:

- **Binding anything other than `127.0.0.1`.** There is deliberately no flag
  for it.
- **Secrets on a command line.** `/proc/<pid>/cmdline` is world-readable.
- **Files written without `0600` in a `0700` directory**, re-applied on every
  write — see `store.write_private`.
- **Skipping host key verification**, even behind an option.
- **Putting a secret in `config.json`.** Passwords, keys, passphrases, TOTP
  secrets and macro bodies live in the encrypted vault, nowhere else.
- **A new runtime dependency** for something a few lines of stdlib can do. The
  app is meant to ship as one self-contained binary.
- **A build step for the frontend.** No npm, no bundler. xterm.js is vendored
  in `eazyconnector/static/vendor/`.

## Style

Match the file you are editing. Comments explain *why*, not *what* — a comment
that restates the code will be asked to go.

Architecture and the roadmap are in [PLAN.md](PLAN.md); packaging in
[PACKAGING.md](PACKAGING.md).
