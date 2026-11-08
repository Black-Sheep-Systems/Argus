#!/usr/bin/env python3
"""Refresh the generated reference block at the end of the Argus manual, with guards.

Rules decide every change. The block between the two GENERATED markers is rebuilt
from the source (sidebar views, helper actions, the app's allowlist) and always sits
after the "Known Gaps" section. The general edition drops that section (make_public
redaction), so the block never reaches it. Nothing else in the inventory changes:
the guard requires every non-blank line outside the block, and every fenced command
block (indented ones included), to be identical to before.

An optional local model (Ollama, loopback http only, redirects and proxies refused)
may write a one-line changelog entry from the rule counts only. Its reply is
sanitised and kept only if it passes the rules; otherwise a rule-made line is written.

Order of writes: both editions are built into a temporary folder first. Then the
inventory is re-read and compared, the editions are moved into the output folder
(a symlink at either destination is refused, and neither may resolve to the
inventory), and finally the inventory is replaced atomically with its permission
bits and line endings kept. A failed build or a changed inventory leaves the
inventory untouched.

Usage:
  update_manual.py --root <Argus repo> --inventory <inventory.md> --build <build_manual.py>
                   --template <manual_template.html> --out <dir> [--log <file>]
                   [--ollama http://127.0.0.1:11434 --model <name>] [--dry-run]

Exit codes: 0 applied or nothing to change, 2 refused by a guard, 1 error.
"""
import argparse
import datetime
import difflib
import glob
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

BEGIN = "[//]: # (GENERATED:begin reference)"
END = "[//]: # (GENERATED:end reference)"
# Link reference definitions render as nothing, so the markers stay invisible in the manual.
BLOCK = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
# A fence at any indentation, closed by a line with the same indentation and fence.
FENCE = re.compile(r"^( *)(`{3,}|~{3,})[^\n]*\n.*?^\1\2[ \t]*$", re.M | re.S)
MAX_REPLY = 200
MAX_BODY = 64 * 1024
TIMEOUT = 300
KEEP_BACKUPS = 20
EDITIONS = ("argus-manual.html", "argus-manual-general.html")

# A bare name is matched as a whole word ("matter" is not "Matt"); identifiers as substrings.
PRIVATE_WHOLE = ["matt"]
PRIVATE = ["mattridge", "matthew", "blksheepltd", "black sheep", "oracle", "129.121.98.1",
           "sha256:gn", "hephaestus-msp", "heph_owner", "newsdesk", "server chat",
           "sentinel", "r-h1", "d:\\github"]


def read_raw(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def read(path):
    """Text with LF line endings, for comparison and editing."""
    return read_raw(path).replace("\r\n", "\n")


def has_private(text):
    """Case-insensitive matches: substrings for identifiers, whole words for bare names."""
    low = text.lower()
    hits = [t for t in PRIVATE if t in low]
    hits += [t for t in PRIVATE_WHOLE
             if re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", low)]
    return hits


def source_facts(root):
    """Read the reference facts straight from the source files."""
    lib = read(os.path.join(root, "native", "src", "lib.rs"))
    m = re.search(r"const ACTIONS: &\[&str\] = &\[(.*?)\];", lib, re.S)
    if not m:
        raise SystemExit("error: native ACTIONS list not found in native/src/lib.rs")
    native = set(re.findall(r'"([a-z0-9-]+)"', m.group(1)))
    # Secret-taking actions go through helper_secret, and status has its own exported function.
    sec = re.search(r"const SECRET_ACTIONS: &\[&str\] = &\[(.*?)\];", lib, re.S)
    if sec:
        native |= set(re.findall(r'"([a-z0-9-]+)"', sec.group(1)))
    native = sorted(native | {"status"})
    helper = read(os.path.join(root, "server", "argus-helper"))
    # The action table: the ACTIONS = { ... } literal at column 0, its keys at 4-space indent.
    start = helper.find("\nACTIONS = {")
    end = helper.find("\n}", start + 1) if start >= 0 else -1
    if start < 0 or end < 0:
        raise SystemExit("error: ACTIONS table not found in server/argus-helper")
    helper_actions = sorted(set(re.findall(r'^    "([a-z0-9-]+)": ', helper[start:end], re.M)))
    html = read(os.path.join(root, "app", "renderer", "index.html"))
    views = sorted(set(re.findall(r'data-view="([a-z-]+)"', html)))
    if not helper_actions or not views:
        raise SystemExit("error: no helper actions or views found; the source layout changed")
    return {"native": native, "helper": helper_actions, "views": views}


def parity_warnings(facts):
    """Actions the app may send but the helper lacks, and the reverse. Reported only."""
    warn = []
    helper, native = set(facts["helper"]), set(facts["native"])
    for a in sorted(native - helper):
        warn.append("warning: app allows '%s' but the helper has no such action" % a)
    for a in sorted(helper - native):
        warn.append("note: helper action '%s' is not in the app's action list" % a)
    return warn


def reference_lines(facts):
    allowed = set(facts["native"])
    lines = ["### Generated reference", "",
             "Built from the source by `tools/update_manual.py`. Do not edit this block by hand.",
             "", "Pages (alphabetical):", ""]
    lines += ["- `%s`" % v for v in facts["views"]]
    lines += ["", "Helper actions, with whether the app calls them through its action list:", ""]
    for a in facts["helper"]:
        lines.append("- `%s`%s" % (a, "" if a in allowed else " (not in the app's action list)"))
    return lines


def build_block(facts):
    return BEGIN + "\n\n" + "\n".join(reference_lines(facts)) + "\n\n" + END


def apply_block(inventory_text, facts):
    """Remove any existing block (wherever it is) and append the fresh one at the end."""
    rest = BLOCK.sub("", inventory_text).rstrip()
    return rest + "\n\n" + build_block(facts) + "\n"


def block_text(text):
    m = BLOCK.search(text)
    return m.group(0) if m else ""


def drift(old_text, new_text):
    """Changed lines inside the generated block (the rule-made changelog source)."""
    return [l for l in difflib.unified_diff(block_text(old_text).splitlines(),
                                            block_text(new_text).splitlines(),
                                            lineterm="", n=0)
            if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]


def outside(text):
    return BLOCK.sub("", text)


def outside_nonblank(text):
    """Non-blank lines outside the block, exact (trailing spaces and indentation kept)."""
    return [l for l in outside(text).split("\n") if l.strip()]


def fenced(text):
    """Fenced code blocks outside the generated block, exact, at any indentation."""
    return [m.group(0) for m in FENCE.finditer(outside(text))]


def build_editions(build_script, template, src, out_dir):
    """Build both editions into out_dir; raises CalledProcessError or TimeoutExpired."""
    os.makedirs(out_dir, exist_ok=True)
    private = os.path.join(out_dir, EDITIONS[0])
    general = os.path.join(out_dir, EDITIONS[1])
    subprocess.run([sys.executable, build_script, src, private, template], check=True, timeout=TIMEOUT)
    subprocess.run([sys.executable, build_script, src, general, template, "--public"],
                   check=True, timeout=TIMEOUT)
    return private, general


def guard(old_text, new_text, build_script, template, tmp):
    """Return reasons to refuse; an empty list means the change may be applied."""
    problems = []
    if len(BLOCK.findall(new_text)) != 1:
        problems.append("the new inventory must contain exactly one generated block")
    if outside_nonblank(old_text) != outside_nonblank(new_text):
        problems.append("text outside the generated block would change")
    if fenced(old_text) != fenced(new_text):
        problems.append("a command block (fenced code) outside the generated block would change")
    for term in has_private(block_text(new_text)):
        problems.append("generated block contains a private term: %s" % term)
    candidate = os.path.join(tmp, "candidate-inventory.md")
    with open(candidate, "w", encoding="utf-8") as f:
        f.write(new_text)
    try:
        _, general = build_editions(build_script, template, candidate, os.path.join(tmp, "check"))
        general_text = read(general)
        leaked = has_private(general_text)
        if leaked:
            problems.append("general edition contains private terms: %s" % ", ".join(leaked))
        if "generated-reference" in general_text.lower():
            problems.append("general edition contains the generated reference")
    except subprocess.CalledProcessError as e:
        problems.append("manual build or redaction check failed (exit %s)" % e.returncode)
    except subprocess.TimeoutExpired:
        problems.append("manual build timed out")
    return problems


CONTROL_AND_MARKUP = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]|[<>{}`*_\[\]()|\\]")


def sanitise(text):
    """Keep one short plain line: no control, direction or zero-width characters, no markup."""
    text = CONTROL_AND_MARKUP.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_REPLY]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError("redirect refused")


def loopback_url(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme != "http" or p.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Ollama must be http on loopback")
    return url.rstrip("/")


def rule_summary(lines, moved):
    if moved and not lines:
        return "Reference block moved to the end; its entries are unchanged"
    if not lines:
        return "Reference block unchanged"
    added = sum(1 for l in lines if l.startswith("+"))
    removed = sum(1 for l in lines if l.startswith("-"))
    return "Reference block updated: %d lines added, %d removed" % (added, removed)


def changelog_text(lines, moved, ollama, model):
    """One line for the log: the local model if it passes the rules, else the rule text."""
    rule_text = rule_summary(lines, moved)
    if not (lines or moved) or not ollama or not model:
        return rule_text
    # The model sees the rule summary only, never the names of pages or actions.
    prompt = ("In one plain sentence under 25 words, say this manual reference changed: "
              + rule_text + ". Output the sentence only.")
    try:
        url = loopback_url(ollama) + "/api/generate"
        body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        # No proxies: the call must reach the loopback address directly. No redirects.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        with opener.open(req, timeout=60) as r:
            raw = r.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            return rule_text
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("response"), str):
            return rule_text
    except Exception:  # the model is optional: any failure falls back to the rule text
        return rule_text
    lines_out = data["response"].strip().splitlines()
    text = sanitise(lines_out[0]) if lines_out else ""
    if len(text) < 10 or has_private(text):
        return rule_text
    return text


def write_atomic(path, text):
    """Replace a file via a temp file in the same folder, keeping its permission bits."""
    if os.path.islink(path):
        raise SystemExit("error: refusing to write through a symbolic link: " + path)
    folder = os.path.dirname(os.path.abspath(path))
    mode = stat.S_IMODE(os.stat(path).st_mode)
    fd, tmp_path = tempfile.mkstemp(dir=folder, prefix=".manual-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def backup_file(path):
    """Copy to a new backup name that is never overwritten and never follows a symlink."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dest = "%s.%s.bak" % (path, stamp)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(dest, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
        out.write(read_raw(path))
    return dest


def prune_backups(path):
    """Keep the newest KEEP_BACKUPS backups of the inventory."""
    backups = sorted(glob.glob(glob.escape(path) + ".*.bak"))
    for old in backups[:-KEEP_BACKUPS]:
        if not os.path.islink(old):
            os.unlink(old)


def check_destinations(out_dir, inventory):
    """Refuse links and any edition path that resolves to the inventory itself."""
    if os.path.islink(out_dir):
        raise SystemExit("error: the output folder is a symbolic link")
    real_inv = os.path.realpath(inventory)
    for name in EDITIONS:
        dest = os.path.join(out_dir, name)
        if os.path.islink(dest):
            raise SystemExit("error: an edition output is a symbolic link: " + dest)
        if os.path.realpath(dest) == real_inv:
            raise SystemExit("error: an edition output would overwrite the inventory: " + dest)


def move_editions(built, out_dir):
    """Move the built editions into the output folder atomically, one at a time."""
    os.makedirs(out_dir, exist_ok=True)
    for src in built:
        dest = os.path.join(out_dir, os.path.basename(src))
        if os.path.islink(dest):
            raise SystemExit("error: an edition output is a symbolic link: " + dest)
        staged = dest + ".new"
        shutil.copyfile(src, staged)
        os.replace(staged, dest)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True)
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--build", required=True)
    ap.add_argument("--template", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--log")
    ap.add_argument("--ollama")
    ap.add_argument("--model")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if os.path.islink(args.inventory):
        raise SystemExit("error: the inventory is a symbolic link; point at the real file")
    if args.log and os.path.islink(args.log):
        raise SystemExit("error: the changelog is a symbolic link")
    check_destinations(args.out, args.inventory)

    facts = source_facts(args.root)
    for w in parity_warnings(facts):
        print(w)

    raw_old = read_raw(args.inventory)
    crlf = "\r\n" in raw_old
    old = raw_old.replace("\r\n", "\n")
    new = apply_block(old, facts)
    if new == old:
        print("no change: the generated block is already current")
        return 0

    lines = drift(old, new)
    moved = not lines
    print("\n".join(lines) if lines else "block moved to the end; no entries changed")

    tmp = tempfile.mkdtemp(prefix="argus-manual-")
    try:
        problems = guard(old, new, args.build, args.template, tmp)
        if problems:
            print("refused:")
            for p in problems:
                print("  - " + p)
            return 2
        if args.dry_run:
            print("dry run: guards passed, nothing written")
            return 0

        # Build the real editions into the temporary folder first.
        build_dir = os.path.join(tmp, "apply")
        try:
            built = build_editions(args.build, args.template, _candidate(tmp, new), build_dir)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print("error: building the editions failed; nothing was changed: %s" % e)
            return 1

        # Last check: the inventory must not have changed while the builds ran.
        if read_raw(args.inventory) != raw_old:
            print("refused: the inventory changed during the update; run it again")
            return 2

        move_editions(built, args.out)
        backup = backup_file(args.inventory)
        to_write = new.replace("\n", "\r\n") if crlf else new
        write_atomic(args.inventory, to_write)
        prune_backups(args.inventory)
        print("applied: inventory updated (backup %s), editions written to %s" % (backup, args.out))

        if args.log:
            try:
                with open(args.log, "a", encoding="utf-8") as f:
                    f.write("- %s: %s\n" % (datetime.date.today().isoformat(),
                                            changelog_text(lines, moved, args.ollama, args.model)))
            except OSError as e:
                print("warning: could not write the changelog: %s" % e)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _candidate(tmp, text):
    path = os.path.join(tmp, "apply-inventory.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


if __name__ == "__main__":
    sys.exit(main())
