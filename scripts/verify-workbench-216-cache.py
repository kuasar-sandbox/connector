#!/usr/bin/env python3
"""Temporary #216 connector cache evidence; remove with the acceptance workflow."""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.parse
import urllib.request


REPOSITORY = "kuasar-sandbox/connector"
ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    path = Path(path).absolute()
    require(path.resolve() == path and stat.S_ISREG(path.lstat().st_mode), "unsafe evidence file: " + str(path))
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def context():
    require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY
            and os.environ["GITHUB_REF"] == "refs/heads/main"
            and os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch", "requires the canonical main dispatch")
    sha = os.environ["TRUSTED_WORKFLOW_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", sha), "missing exact workflow revision")
    return {"repository": REPOSITORY, "ref": "refs/heads/main", "source_sha": sha,
            "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"]}


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True, timeout=60).strip()


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", "repos/" + path], text=True, timeout=60))


def caches(key=None):
    # Cache inventory of this public repository needs no additional token
    # permission. This helper never deletes a cache or requests a write token.
    rows = []
    for page in range(1, 101):
        query = {"ref": "refs/heads/main", "per_page": 100, "page": page}
        if key:
            query["key"] = key
        request = urllib.request.Request(
            "https://api.github.com/repos/" + REPOSITORY + "/actions/caches?" + urllib.parse.urlencode(query),
            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(request, timeout=30) as response:
            part = json.load(response)["actions_caches"]
        rows.extend(row for row in part if key is None or row["key"] == key)
        if len(part) < 100:
            return rows
    raise ValueError("cache inventory exceeded its bounded pagination budget")


def freeze(args):
    frozen = context()
    repository = api(REPOSITORY)
    require(repository["full_name"] == REPOSITORY and repository["private"] is False
            and repository["visibility"] == "public", "repository is not canonical and public")
    require(git(ROOT, "rev-parse", "HEAD") == frozen["source_sha"]
            == api(REPOSITORY + "/git/ref/heads/main")["object"]["sha"],
            "workflow source is no longer the exact admitted main head")
    framework = Path("trusted/platform")
    frozen["framework_sha"] = git(framework, "rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", frozen["framework_sha"]), "missing exact framework revision")
    args.plan.mkdir()
    # The framework checkout resolves main once; every following Job checks out
    # this SHA. The published image selector likewise runs only here.
    subprocess.run(["python3", "-B", str(framework / "ci/hosted/workbench.py"), "select",
                    "--framework-sha", frozen["framework_sha"], "--output", str(args.plan / "workbench.json")],
                   check=True, timeout=600)
    frozen["selection"] = read(args.plan / "workbench.json")
    frozen["version"] = "v0.0.0"  # Local package validation only; never a tag or release.
    frozen["cache_before"] = caches()
    write(args.plan / "frozen.json", frozen)
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        for field in ("source_sha", "framework_sha"):
            stream.write(field + "=" + frozen[field] + "\n")


def digest(path):
    path = path.absolute()
    require(path.resolve() == path and stat.S_ISREG(path.lstat().st_mode), "unsafe product: " + str(path))
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def record(args):
    args.output.mkdir(parents=True)
    result = {"phase": args.phase, "arch": args.arch, "conclusion": "failure"}
    try:
        frozen = read(args.plan / "frozen.json")
        require(all(frozen.get(key) == value for key, value in context().items()), "foreign frozen input")
        selection = read(args.plan / "workbench.json")
        require(selection == frozen["selection"], "image selection changed after prepare")
        temporary = Path(os.environ["RUNNER_TEMP"])
        require(not (temporary / "kuasar-workbench").exists(), "Workbench private state was not removed")
        paths = list(temporary.glob("workbench-evidence-*/receipt.json"))
        scopes = list(temporary.glob("workbench-cache-scope-" + frozen["run_id"] + "-*.json"))
        require(len(paths) == len(scopes) == 1, "expected exactly one Workbench instance and admission receipt")
        receipt, scope = read(paths[0]), read(scopes[0])
        result.update(frozen=frozen, receipt=receipt, cache_scope=scope)
        # Only host-created receipts and regular product files are read after
        # the shared action has stopped and deleted this instance. No host Git
        # or candidate script executes after the build.
        require(receipt["conclusion"] == "success" and receipt["cleanup_exit_code"] == 0
                and receipt["delete_output_exit_code"] == 0, "build or owned resource cleanup failed")
        instance = read(paths[0].parent / "instance.json")
        require(instance["status"] == "cleaned" and instance["owner_uid"] == os.getuid(), "instance was not cleaned by its owner")
        require(receipt["owner_uid"] == os.getuid() != 0 and receipt["mode"] == "build"
                and receipt["arch"] == args.arch and receipt["cpus"] == 2 and receipt["memory_gib"] == 8,
                "ordinary UID, native architecture or task budget differs")
        require(receipt["framework_sha"] == frozen["framework_sha"] and receipt["selection"] == selection,
                "framework or image selection differs")
        require(all(receipt["image"].get(key) == value for key, value in selection["architectures"][args.arch].items()),
                "immutable native image differs")
        source_root = str(Path("src").resolve())
        require(receipt["sources"] == source_root and scope["source_root"] == source_root
                and scope["repository"] == REPOSITORY and scope["ref"] == "refs/heads/main"
                and scope["event"] == "workflow_dispatch" and scope["run_id"] == frozen["run_id"]
                and scope["scope"] == scope["namespace"] == "trusted"
                and scope["event_inputs"] == {} and scope["transport"] == {}, "cache is not this repository's trusted main namespace")
        require(len(scope["sources"]) == 1, "unexpected source or task material in the cached build")
        source = scope["sources"][0]
        require(source["path"] == "connector" and source["kind"] == "git" and source["clean"] is True
                and source["on_main"] is True and source["repository"] == REPOSITORY
                and source["sha"] == frozen["source_sha"], "cache source admission differs")
        commands = receipt["commands"]
        require(commands and all(row["exit_code"] == 0 for row in commands), "a build command failed or was interrupted")
        require(commands[-1]["argv"][:4] == ["bash", "-euo", "pipefail", "-c"], "owner release commands did not run")
        expiry = [index for index, row in enumerate(commands) if row["argv"] == ["go", "clean", "-testcache"]]
        require(len(expiry) == 1 and expiry[0] < len(commands) - 1,
                "restored Go test results were not expired before owner execution")
        cache = receipt["cache"]
        coverage = hashlib.sha256(json.dumps({"schema": 1, "kind": "release-connector", "arch": args.arch,
                                             "native": []}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        require(cache["WB_CACHE"] == "true" and cache["WB_CACHE_COVERAGE"] == "release-connector"
                and re.fullmatch("workbench-v2-" + args.arch + "-trusted-" + coverage + "-[0-9a-f]{64}", cache["WB_CACHE_KEY"]),
                "cache coverage, architecture or trusted key differs from normal release")
        bundle = Path("src/connector/release-bundle")
        expected = {"assets/connector-v0.0.0-linux-" + args.arch + ".tar.gz", "assets/SHA256SUMS", "release-notes.md"}
        require({str(path.relative_to(bundle)) for path in bundle.rglob("*") if not path.is_dir()} == expected,
                "unexpected packaged file set")
        result["package_sha256"] = {name: digest(bundle / name) for name in sorted(expected)}
        result["product_sha256"] = digest(Path("src/connector/bin") / args.arch / "connector-ctl")
        result["cache_inventory"] = caches(cache["WB_CACHE_KEY"])
        require(len(result["cache_inventory"]) == 1, "expected one saved exact key in this repository")
        saved = result["cache_inventory"][0]
        require(saved["ref"] == "refs/heads/main" and saved["size_in_bytes"] > 0, "empty or foreign saved cache")
        if args.phase == "cold":
            require(cache["WB_CACHE_HIT"] == "" and cache["WB_MATCHED_KEY"] == "",
                    "initial Job used an existing cache; preserved as observed, not a cold/save success")
            require(not any(row["key"] == cache["WB_CACHE_KEY"] for row in frozen["cache_before"]),
                    "exact key already existed before this run; cannot attribute a new save")
            created = datetime.fromisoformat(saved["created_at"].replace("Z", "+00:00")).timestamp()
            require(receipt["started_ns"] / 1e9 - 2 <= created <= time.time() + 2,
                    "saved cache was not created during this cold Job")
            result["cache_save_evidence"] = "miss, new exact cache object and creation time; audit the cold Job Cache saved with key log"
        else:
            require(cache["WB_CACHE_HIT"] == "true" and cache["WB_MATCHED_KEY"] == cache["WB_CACHE_KEY"],
                    "fresh Job did not restore the exact cache key")
            cold = read(args.cold / "result.json")
            require(cold["conclusion"] == "success" and cold["phase"] == "cold" and cold["arch"] == args.arch
                    and cold["frozen"] == frozen, "cold evidence is incomplete or uses different inputs")
            require(cold["receipt"]["cache"]["WB_CACHE_KEY"] == cache["WB_CACHE_KEY"]
                    and cold["cache_inventory"][0]["id"] == saved["id"], "warm Job restored a different cache")
            require(cold["product_sha256"] == result["product_sha256"]
                    and cold["package_sha256"] == result["package_sha256"], "warm build changed product or packaged source/license materials")
            result["comparison"] = "same product and package bytes after fresh-Job exact restore; Go build still executes"
        result["conclusion"] = "success"
    except (KeyError, OSError, ValueError) as error:
        result["error"] = str(error)
        raise
    finally:
        write(args.output / "result.json", result)
        print(json.dumps({key: result[key] for key in ("phase", "arch", "conclusion", "error") if key in result}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("freeze")
    prepare.add_argument("--plan", type=Path, required=True)
    observe = sub.add_parser("record")
    observe.add_argument("--plan", type=Path, required=True)
    observe.add_argument("--phase", choices=("cold", "warm"), required=True)
    observe.add_argument("--arch", choices=("x86_64", "aarch64"), required=True)
    observe.add_argument("--output", type=Path, required=True)
    observe.add_argument("--cold", type=Path)
    args = parser.parse_args()
    if args.command == "freeze":
        freeze(args)
    else:
        require(args.phase == "cold" or args.cold is not None, "warm comparison needs the completed cold Job evidence")
        record(args)


if __name__ == "__main__":
    main()
