# Lab Handoff & Phase 2 Status

**Date:** 2026-07-17 · **Branch:** `develop` · **Status:** first end-to-end run completed successfully

This document covers three things: the lab we built, how teammates connect to it, and where Phase 2 stands.

---

## 1 · What exists now

Before today the framework had never been run end-to-end. It now has: a dedicated controller VM, a working
connection to the LLM, and a completed audit against a real target that produced a 16-page PDF report.

### Network layout

```
Your PC ──Tailscale──▶ 192.168.1.0/24 (Xar's house LAN)
                          ├── 192.168.1.158  Proxmox host "Xardana" (:8006 web UI)
                          ├── 192.168.1.89   Xar's Mac — Ollama (:11434)
                          └── 192.168.1.90   controller (VM 201) ◀── you SSH here
                                    │
                                    │ (second NIC)
                                    ▼
                        10.10.10.0/24 "LANPF" — behind pfSense (gateway 10.10.10.1)
                          ├── 10.10.10.104   controller (same box, other NIC)
                          └── 10.10.10.103   lain205 (VM 205) — audit target
```

### VMs on Proxmox (node `Xardana`)

| ID | Name | Role | Notes |
|----|------|------|-------|
| 200 | pfSense | Lab router | LAN `10.10.10.1`. NATs LANPF → house LAN. Don't audit it. |
| 201 | **controller** | **Runs the framework** | Ubuntu 24.04.4 Server. Dual-homed. Built today. |
| 202 | Win10 | Target | Not set up yet — see §5 |
| 203 | Win11 | Target | Not set up yet — see §5 |
| 204 | Ubuntu1 | Target | Not set up yet |
| 205 | lain205 | **Target — tested** | Seeded with deliberate vulns |

### Why the controller has two network cards

This is the important bit, and it's non-obvious.

- **`ens18` → `10.10.10.104`** on LANPF. This is how the framework reaches targets. It's the working interface.
- **`ens19` → `192.168.1.90`** on the house LAN. This is how *humans* reach the controller.

The second NIC exists because **Tailscale's ACL blocks the controller's tailnet address** (`100.114.179.83`).
The tailnet is `xardana.github` — Xar is the admin, we're members, and no ACL rule covers a new node we add.
`tailscale ping` works (it bypasses ACLs) but TCP does not, so SSH fails with a misleading
`Permission denied` at connect time.

Rather than wait on an ACL change, the controller was given a second NIC on the house LAN — which we can already
reach, because that's the same path we use for the Proxmox web UI. **Use `192.168.1.90`. Ignore the `100.x` address.**

The architecture is unaffected: the framework still talks to targets over LANPF exactly as designed. The second
NIC is a management interface, nothing more.

---

## 2 · Connecting with VS Code (for teammates)

### Prerequisites

1. **Tailscale**, signed in to the `xardana.github` tailnet, with the subnet route to `192.168.1.0/24` accepted.
   You have this already if `https://192.168.1.158:8006` (Proxmox) loads for you.
2. **VS Code** with the **Remote - SSH** extension:
   ```
   code --install-extension ms-vscode-remote.remote-ssh
   ```
   Install "Remote - SSH" by Microsoft (`ms-vscode-remote.remote-ssh`). Not "Remote Tunnels" — different thing.

### Get an account on the controller

Ask for one rather than sharing a login. On the controller:

```bash
sudo adduser <yourname>
sudo mkdir -p /home/<yourname>/.ssh
# paste your public key into /home/<yourname>/.ssh/authorized_keys
sudo chown -R <yourname>:<yourname> /home/<yourname>/.ssh
sudo chmod 700 /home/<yourname>/.ssh && sudo chmod 600 /home/<yourname>/.ssh/authorized_keys
```

No public key yet? On your own machine:

```bash
ssh-keygen -t ed25519 -C "lain-<yourname>"
cat ~/.ssh/id_ed25519.pub
```

> ⚠️ **`ssh-keygen` silently destroys an existing key if you answer "overwrite: y".** Check for
> `~/.ssh/id_ed25519` first. This bit one of us today — an unrelated key from last October is gone.

### Connect

1. `Ctrl+Shift+P` → **Remote-SSH: Connect to Host**
2. Enter `<yourname>@192.168.1.90`
3. Config file → pick `C:\Users\<you>\.ssh\config` (the user one, no admin needed)
4. Platform → **Linux**
5. Verify the host fingerprint: `SHA256:hdS+ILo2eMiFev44hN3EVBYApTuWrNYpy9nRosuvx3A`
6. **File → Open Folder** → `/home/<yourname>/LAIN-Security-Framework`

First connect takes ~30s while VS Code installs its server. Instant after that.

### Nice to have

Add to your local `~/.ssh/config` so you can type `ssh controller`:

```
Host controller
    HostName 192.168.1.90
    User <yourname>
    IdentityFile ~/.ssh/id_ed25519
```

### GitHub access from the controller

The repo is private (`Xardana/LAIN-Security-Framework`), and GitHub dropped password auth for git in 2021.
Each person needs an SSH key **on the controller** added to their **own** GitHub account — collaborator access
comes along with it, no repo-owner action needed.

```bash
ssh-keygen -t ed25519 -C "lain-controller-<yourname>"
cat ~/.ssh/id_ed25519.pub          # paste into GitHub → Settings → SSH and GPG keys
ssh -T git@github.com              # expect: "Hi <user>! You've successfully authenticated"
git clone git@github.com:Xardana/LAIN-Security-Framework.git
```

GitHub's real host fingerprint is `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` (ED25519) — worth
checking rather than blindly typing `yes`.

---

## 3 · Running the framework

```bash
cd ~/LAIN-Security-Framework
git checkout develop
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

`.env` — not in git, create it yourself:

```
AI_API_BASE_URL=http://192.168.1.89:11434/v1
AI_MODEL=qwen2.5-coder:14b
AI_API_KEY=ollama
```

Give the controller a key onto the target, then run:

```bash
ssh-copy-id lain205@10.10.10.103
python3 src/main.py --target 10.10.10.103 --user lain205
```

Outputs land in `reports/audit_report.pdf`, `logs/audit_*.json`, and `generated_scripts/`.

### Test in stages, not all at once

A full run touches Tailscale, Ollama, SSH and a 6-task loop. If it breaks you won't know which. Isolate:

```bash
# 1. Ollama reachable + your parser works?
python3 -c 'import sys; sys.path.insert(0,"src"); import ai_client; print(ai_client.send("Reply with only JSON.", "Return a JSON object with key ok set to true"))'

# 2. SSH + profile parsing work?
python3 -c 'import sys; sys.path.insert(0,"src"); import target_connector, system_profile; print(system_profile.parse(target_connector.collect_system_info("10.10.10.103","lain205")))'

# 3. Full run
python3 src/main.py --target 10.10.10.103 --user lain205
```

---

## 4 · Code changes made today

All on `develop`, commit **`9f2195e`** — "Fix validator false positives and execution bugs".

### `validator.py` — it was rejecting the scripts the framework asks for

| Pattern | Problem |
|---|---|
| `\bcompile\s*\(` | Also matched `re.compile(` — **every script using regex was rejected**, and parsing `ss` output needs regex |
| `\bsudo\b` / `\bsetuid\b` | Matched the words anywhere, including comments and finding titles — while `prompt_builder` explicitly asks for sudo/wheel group membership and SUID files |
| `\.connect\s*\(` | Matched `sqlite3.connect("file.db")` |

Fixed by matching the **dangerous act, not the word**: sudo as a command or as argv[0]; `os.setuid(` over bare
`setuid`; `socket.socket(` over any `.connect(`. Comments are now stripped via `tokenize` before matching, with
a fallback to raw text if the script won't parse.

**Rule for adding patterns later: match acts, not words.** And test both directions — realistic audit scripts must
PASS, dangerous ones must still BLOCK. A tightening that only checks for false positives will silently gut the
validator. There's a 21-case suite pattern that works.

### `target_connector.py` — two real bugs

- **`python3 x || python x` ran the script twice.** `||` fires on *any* nonzero exit, not just a missing python3.
  A script that merely errored produced two JSON objects on stdout, which `report_writer` couldn't parse. Now an
  `if/else` picks the interpreter and runs it exactly once.
- **Cleanup was fire-and-forget.** `exec_command` only *sends* the request; the connection closed before the target
  ran the delete, so temp scripts were being left behind on every run. Now it waits for completion.

### Timeouts everywhere

`CONNECT_TIMEOUT=15`, `COMMAND_TIMEOUT=30`, `SCRIPT_TIMEOUT=120`, plus `REQUEST_TIMEOUT=180` on the Ollama call.
Without them a stalled script or dropped link hung the run forever with no output and no error. A single slow
enumeration command now records a blank and continues rather than losing the whole profile.

---

## 5 · Need-to-know going forward

### 🔴 The findings are wrong — and this is Phase 3's whole justification

The first run was a *success*: 6/6 tasks approved on attempt 1, 20 findings, clean PDF. Then we checked the findings
against reality:

- **The only HIGH finding is `/dev/null`.** The script reported
  `/etc/systemd/system-generators/systemd-gpt-auto-generator` as world-writable. Its `st_mode=8630` decodes to
  `0o20666` — a **character device**, mode 666, size 0. That generator is *masked* (systemd masks units by
  symlinking them to `/dev/null`), and the script used `os.stat()` (follows symlinks) instead of `os.lstat()`.
- **The seeded backdoor was missed.** `lain-backdoor.service` runs `nc -lk -p 1234`. The script ran `ss -tulpn`
  and read `parts[3]` — correct for `ss -tlnp`, but **the `-u` flag adds a `Netid` column and shifts everything by
  one**, so `parts[3]` is Send-Q. `nc`'s listen backlog is 1, so the backdoor was reported as **"Listening port 1"**.
  All the other rows have backlog 4096 → "Listening port 4096" ×4.
- **13 MEDIUMs describe stock Ubuntu.** `sudo`, `passwd`, `chsh`, `mount`… every Ubuntu has these SUID. Three are
  double-counted — `sudo`/`sudoedit`, `sg`/`newgrp`, `fusermount`/`fusermount3` share inodes; the same file twice.
- **The LOW is a misread error.** "Restrictive Default iptables Policy" — evidence field literally reads
  `Failed running ['iptables', '-S']`. Non-root can't read iptables; the script concluded a firewall policy from
  a failure.
- **Three tasks reported *completed, 0 findings*** on a deliberately-vulnerable box.

**Not one finding is both correct and actionable.** Every script was safe, valid, read-only, schema-perfect — and
wrong.

The takeaway, and the thing worth building Phase 3 around: **the validator proves a script is *safe*; nothing proves
it is *correct*.** Those are independent properties, and an LLM's failure mode isn't a crash — it's confident,
well-formatted nonsense that passes every check you own.

Two structural conclusions for Phase 3:

1. **Stop asking the model to write parsers.** Collect data deterministically in `target_connector.py` (we already
   do this correctly for the system profile) and let the model **interpret** rather than **extract**. `parts[3]`,
   `os.stat` vs `os.lstat`, and "the command failed so the firewall must be strict" are all extraction bugs.
2. **Findings need ground truth.** A baseline of expected SUID binaries kills 13 noise findings. Deduping by inode
   kills 3 more. Checking `returncode` before drawing conclusions kills another.

One design detail worth keeping: the **`evidence` field saved us.** The title said "Listening port 1", but the
evidence read `tcp LISTEN 0 1 0.0.0.0:1234` — the truth survived the parse bug because the schema demanded raw
output. That field is doing more work than anything else in the design.

### 🟡 Known bugs left unfixed (deliberately)

- **`system_profile.py` — memory is the header row.** The PDF prints
  `Memory: total used free shared buff/cache available` because `_first_line()` on `free -h` returns the column
  headings; the numbers are on the `Mem:` line. Cosmetic (memory isn't sent to the model) but visible in the report.
- **`ai_client.py` — `content=None` crashes.** `message.content` can be `None`; `json.loads(None)` raises
  `TypeError`, not `JSONDecodeError`, so it escapes the handler and surfaces as
  `[FATAL] the JSON object must be str, bytes or bytearray, not NoneType`. Normal Ollama behaviour. Hasn't hit yet.
- **`ai_client.py` — non-dict JSON crashes.** `json.loads` can return a `str`/`list`, which then hits
  `.get("script")` → `AttributeError`.
- **`ai_client.py:91`** — `json_block.group(1)` alone on a line, result discarded. Dead code.
- **`system_profile.py`** — `_parse_privilege` uses `user.endswith("root")`, so `chroot`/`nonroot` report as root.
- **No check that the "script" is actually Python.** If the model *refuses* a task, the refusal text becomes
  `script`, passes the validator (no blocked patterns in an apology), gets uploaded, and dies as a syntax error on
  the target. An `ast.parse()` check would turn that into *"the model refused, here's what it said"*.

### 🟡 Recommended before heavy Phase 3 use

Add `extra_body={"format": "json"}` and `temperature=0.2` to the Ollama call. The `OUTPUT_CONTRACT` asks for JSON
*containing a script that itself prints different JSON* — a lot of nested-schema discipline for a small model.

### 🟡 Model choice

`.env.example` still names `huihui_ai/foundation-sec-abliterated`. Ollama reports its capabilities as
`["completion"]` only — no tools, no structured-output training. It's a security *knowledge* model, but the task is
*write Python and wrap it in strict nested JSON*.

`qwen2.5-coder:14b` reports `["completion","tools","insert"]`, is nearly twice the size, and returned **bare valid
JSON on the first try** with no fence and no prose. That's what today's successful run used.

Worth comparing them properly for Phase 3 — *"the security-specialised model couldn't hold the output contract;
the code model could"* is a real finding, and the comparison is already half-promised in the milestone doc.

### 🟡 Things that will break again

- **The Mac's IP moves.** It was `192.168.1.103`, a power cut rebooted it, and it came back as `192.168.1.89` —
  outside the `.100–.130` range we were told to scan, so a port sweep couldn't have found it either. Ask Xar for a
  DHCP reservation, or put Tailscale on the Mac for an address that never changes.
- **`OLLAMA_HOST` doesn't survive a reboot.** `launchctl setenv OLLAMA_HOST "0.0.0.0:11434"` is session-scoped.
  If Ollama starts refusing connections (as opposed to timing out), that's why — it's bound to `127.0.0.1` again.
  Persistence needs a LaunchAgent plist.
- **The controller's `192.168.1.90` is a DHCP lease.** Same failure mode. Worth pinning static or reserving.
- **Diagnostic worth remembering:** *timed out* ≠ *refused*. A refusal means the host answered (something's alive,
  wrong port/binding). A timeout means nothing answered (host down/asleep/dropping). That distinction saved an hour.

### 🟢 Windows targets (202/203) — not started

Needed before they can be audited, and they're the weakest code path:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Set-Service -Name sshd -StartupType Automatic
```

Three traps waiting:
1. **Python isn't installed**, and Windows ships a fake `python.exe` App Execution Alias that silently opens the
   Microsoft Store. You'd get empty output and no error. Install real Python, disable the alias.
2. **Don't change OpenSSH's default shell.** `target_connector.py` uses `echo %TEMP%` and `del /f /q`, which assume
   `cmd.exe`. If PowerShell is set as default, `echo %TEMP%` returns the literal string and the upload lands nowhere.
3. **`authorized_keys` moves for admins** — accounts in Administrators read
   `C:\ProgramData\ssh\administrators_authorized_keys` instead of `~/.ssh/authorized_keys`. Use a non-admin
   `auditor` account and the normal path works.

---

## 6 · Phase 2 status

### Done

| Deliverable | Where |
|---|---|
| Flowchart — current elements + clearly distinguished "still to come" | `docs/PHASE3_MILESTONE.md` §1 + `docs/phase3_flowchart.mmd`. Blue solid = working, amber dashed = "Not Yet Built", with legend. |
| Detailed write-up of what's completed by Phase 3 | `docs/PHASE3_MILESTONE.md` §2 — 16 items, each with scope and a Definition of Done |
| Source code, `.py` files | `src/` — 7 modules, ~1,400 lines |
| All 5 mandatory elements, called out in comments | ✅ verified — see below |
| **A working end-to-end demo** | Real target, self-hosted LLM, 6/6 tasks, 16-page PDF |

### The 5 mandatory coding elements

| Element | Marked at |
|---|---|
| Functions | `main.py:20`, `report_writer.py:35` |
| Classes | `report_writer.py:132` (`_AuditPDF`) |
| Casting | `report_writer.py:46,75,213,286,406`, `prompt_builder.py:118,133`, `system_profile.py:29`, `target_connector.py:88` |
| Modules `os` + `sys` | `main.py:8` (os), `main.py:9,178` (sys), also `report_writer.py:10`, `ai_client.py:41` |
| File handling | `report_writer.py:420,438` |

Soft spot: `_AuditPDF` is the **only class in the project**. It's marked and it counts, but "impressive verbosity
worth ~7 weeks" and one thin FPDF subclass sit a little awkwardly together. Worth a sentence on camera about *why*
it's a class (it subclasses FPDF to get header/footer/pagination for free) rather than hoping it goes unnoticed.

### Still needed

1. **AI usage statement — `docs/disclosure-statement.md` is 0 bytes.** The Phase 2 100% rubric explicitly lists
   *"AI usage stated"*, and Phase 1 required a disclosure statement (the brief attaches academic-misconduct risk to
   failing to disclose). **This is the only rubric line currently unmet.** ~15 minutes.
   > `docs/flowchart.md` and `docs/project-proposal.md` are also 0 bytes. The flowchart lives in
   > `PHASE3_MILESTONE.md` so that's covered — but empty files in `docs/` invite a reviewer to open them.
   > Fill or delete.

2. **Video — 5 minutes, strictly enforced.** 50% of the grade.
   - **0:30 — Elevator pitch.** The first line of `PHASE3_MILESTONE.md` is already tight enough to read aloud.
   - **2:00 — Demonstration.** `python3 src/main.py --target 10.10.10.103 --user lain205`, then the PDF. This is a
     genuinely strong demo: real target, self-hosted LLM, safety validation, generated report.
   - **2:30 — Code walkthrough.** Point at the five elements from the table above. Then spend 30s on
     `validate_with_retries` taking `generate` as a callback — it's the most interesting design decision in the
     codebase and it shows you understand your own code, which is exactly what the rubric rewards.

3. **Two polish items before recording:**
   - **The memory header bug** — page 2 of the PDF shows `Memory: total used free shared buff/cache available`.
     ~10 lines in `system_profile.py`.
   - **The flowchart names the wrong model** — it says `foundation-sec 8B / 192.168.1.103`, but the demo will run
     `qwen2.5-coder:14b` on `192.168.1.89`. A reviewer who reads the diagram and watches the demo will notice.

### Don't mention the findings bug in the Phase 2 video

It's the most interesting thing we learned, but Phase 2 asks for *"what's been completed so far"* in a strict
5-minute window. It costs time and muddies a working demo. **Save it for Phase 3** — it's the evidence that
justifies the Enhanced Validation and Explainable Reporting scope you already promised, and it'll make that video
far stronger.

---

## Quick reference

| | |
|---|---|
| Controller (humans) | `192.168.1.90` — SSH, VS Code |
| Controller (framework→targets) | `10.10.10.104` |
| Controller tailnet addr | `100.114.179.83` — **ACL-blocked, don't use** |
| Target | `10.10.10.103` (lain205), user `lain205` |
| Ollama | `http://192.168.1.89:11434/v1`, model `qwen2.5-coder:14b` |
| Proxmox | `https://192.168.1.158:8006`, node `Xardana` |
| pfSense | `10.10.10.1` |
| Repo | `git@github.com:Xardana/LAIN-Security-Framework.git`, branch `develop` |
| Controller SSH fingerprint | `SHA256:hdS+ILo2eMiFev44hN3EVBYApTuWrNYpy9nRosuvx3A` |
