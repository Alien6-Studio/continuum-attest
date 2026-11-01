#!/usr/bin/env python3
"""Break producer protections in an otherwise unused clean checkout.

Requires the real Tessera conformance writer. Each mutated binary must compile,
and the full qualification must fail at the specified assertion. Sources are
restored in finally blocks; never run beside another editor or build.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


CASES = [
    ("durable-intent", "src/publication/client.rs",
     "// This is the disclosure boundary: record exact intent before POST.\n        store.save(record, false)?;",
     "// Mutation: omit durable intent before POST.", "disclosure preceded durable intent"),
    ("bounded-retries", "src/publication/record.rs",
     "pub const MAX_SUBMISSIONS: usize = 3;", "pub const MAX_SUBMISSIONS: usize = 4;",
     'assert len(record["submissions"]) <= 3'),
    ("overall-deadline", "src/publication/client.rs",
     "tokio::time::timeout(timeout, obtain_inclusion(&log, config, &mut record, &store))",
     "tokio::time::timeout(Duration::from_secs(120), obtain_inclusion(&log, config, &mut record, &store))",
     "assert time.monotonic() - started < timeout + 5"),
    ("required-cli-policy", "src/main.rs",
     'if status == "unconfirmed" && args.publication_policy == "required"',
     'if false && status == "unconfirmed" && args.publication_policy == "required"',
     "expected 3, got 0"),
    ("required-ci-policy", "ci-templates/github/attest-action/run.py",
     'if (status.get("log_publication_policy") == "required"',
     'if (False and status.get("log_publication_policy") == "required"',
     "expected 3, got 0"),
    ("build-exit-priority", "ci-templates/github/attest-action/run.py",
     "if build is not None and build != 0:", "if False and build is not None and build != 0:",
     "expected 37, got 3"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tessera", type=Path, required=True)
    parser.add_argument("--keygen", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--filter", default="")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    for check in [["git", "diff", "--quiet"], ["git", "diff", "--cached", "--quiet"]]:
        if subprocess.run(check, cwd=root).returncode:
            raise RuntimeError("producer mutation gate requires an unused clean checkout")
    selected = [case for case in CASES if args.filter in case[0]]
    if not selected:
        raise RuntimeError("no producer mutation matched")
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)

    def build():
        result = subprocess.run(["cargo", "build", "--bin", "attest", "--locked"], cwd=root,
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError("mutated source did not compile; no protection was tested\n" + result.stderr)

    def qualify(name):
        return subprocess.run([sys.executable, str(root / "tools/qualify-publication.py"),
                               "--attest", str(root / "target/debug/attest"),
                               "--tessera", str(args.tessera.resolve()), "--keygen", str(args.keygen.resolve()),
                               "--output", str(output / name)], cwd=root, capture_output=True, text=True,
                              timeout=180)

    build()
    baseline = qualify("baseline")
    if baseline.returncode:
        raise RuntimeError("unmodified qualification failed\n" + baseline.stdout + baseline.stderr)
    results = []
    for name, filename, before, after, marker in selected:
        path = root / filename
        original = path.read_text()
        if original.count(before) != 1:
            raise RuntimeError(f"{name}: mutation no longer applies")
        mutated = original.replace(before, after)
        try:
            path.write_text(mutated)
            build()
            result = qualify(name)
            if result.returncode == 0 or marker not in result.stdout + result.stderr:
                raise RuntimeError(f"{name}: qualification did not fail at the expected assertion\n"
                                   + result.stdout + result.stderr)
            results.append(name)
            print(f"ok producer mutation: {name}", flush=True)
        finally:
            if path.read_text() != mutated:
                raise RuntimeError("concurrent source change: inspect checkout before restoring")
            path.write_text(original)
    build()
    (output / "mutations.json").write_text(json.dumps({"baseline": "passed", "caught": results}, indent=2) + "\n")
    print(f"producer mutation gate: {len(results)} protections caught", flush=True)


if __name__ == "__main__":
    main()
