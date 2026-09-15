#!/usr/bin/env python3
"""Enforce PLAN2's exact direct and active transitive dependency policy.

Cargo tree selects active normal/build edges separately for each target.
Cargo metadata supplies package details; it may also contain inactive optional
edges. Inactive packages in Cargo.lock are reported separately.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import tomllib

class AuditError(ValueError):
    pass

NEW = {
    "smoltcp": ("0.12.0", "std medium-ip proto-ipv4 proto-ipv6 socket-tcp socket-udp"),
    "rustls": ("0.23.45", "std tls12 custom-provider"),
    "rustls-rustcrypto": ("0.0.2-alpha", "std tls12 zeroize"),
    "p256": ("0.13.2", "std ecdsa pkcs8"),
    "p384": ("0.13.1", "std ecdsa"),
    "ed25519-dalek": ("2.2.0", "std"),
    "ed448-goldilocks-plus": ("0.16.0", "std signing pkcs8"),
    "x509-cert": ("0.2.5", "std builder"),
    "sha1": ("0.10.7", "std"),
}
BASE = {"libc": "0.2.177", "getrandom": "0.3.4", "libloading": "0.8.9"}
FORBIDDEN = {"ring", "aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys", "openssl", "openssl-sys",
             "native-tls", "openssl-src", "cc", "cmake", "security-framework", "schannel"}


def check_manifest(manifest):
    dependencies = manifest.get("dependencies", {})
    if set(dependencies) != set(NEW) | set(BASE):
        raise AuditError("direct dependency set differs from the 12 exact PLAN2 crates")
    if any(manifest.get(k) for k in ["build-dependencies", "dev-dependencies", "target", "patch", "replace", "workspace"]):
        raise AuditError("unaccounted build/dev/target/workspace dependencies or overrides")
    for name, version in BASE.items():
        dep = dependencies[name]
        req = dep if isinstance(dep, str) else dep.get("version")
        if req != "=" + version:
            raise AuditError(f"{name}: baseline pin changed")
    if dependencies["libloading"] != {"version": "=0.8.9", "optional": True}:
        raise AuditError("libloading must remain the optional dynamic pcap adapter")
    for name, (version, features) in NEW.items():
        dep = dependencies[name]
        if not isinstance(dep, dict) or dep.get("version") != "=" + version or dep.get("default-features") is not False:
            raise AuditError(f"{name}: exact pin and disabled defaults required")
        if sorted(dep.get("features", [])) != sorted(features.split()):
            raise AuditError(f"{name}: features differ from PLAN2")
        if set(dep) != {"version", "default-features", "features"}:
            raise AuditError(f"{name}: unexpected dependency override")


def active_packages(metadata):
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    packages = {p["id"]: p for p in metadata["packages"]}
    seen, pending = set(), [metadata["resolve"]["root"]]
    while pending:
        ident = pending.pop()
        if ident in seen:
            continue
        if ident not in nodes or ident not in packages:
            raise AuditError("incomplete Cargo dependency graph")
        seen.add(ident)
        for dep in nodes[ident]["deps"]:
            if any(k["kind"] in (None, "normal", "build") for k in dep["dep_kinds"]):
                pending.append(dep["pkg"])
    return [packages[i] for i in sorted(seen)]


def check_packages(packages, allowed):
    for p in packages:
        name, version = p["name"], p["version"]
        if name in FORBIDDEN or p.get("links"):
            raise AuditError(f"active native dependency: {name} {version}, links={p.get('links')}")
        if (name, version) not in allowed:
            raise AuditError(f"unaccounted active package/version: {name} {version}")


def allowed_packages(plan, package):
    appendix = plan.split("## Appendix A.", 1)[1]
    transitive = re.findall(r"^\| `([^`]+)` \| `([^`]+)` \|", appendix, re.M)
    if len(transitive) != 99 or len(set(transitive)) != 99:
        raise AuditError("Appendix A must contain 99 unique exact transitive pins")
    return set(transitive) | {(n, v[0]) for n, v in NEW.items()} | set(BASE.items()) | {
        ("cfg-if", "1.0.4"), (package["name"], package["version"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--locked", action="store_true")
    parser.add_argument("--all-features", action="store_true")
    parser.add_argument("--targets", default="x86_64-unknown-linux-gnu,x86_64-apple-darwin,aarch64-apple-darwin")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    try:
        manifest = tomllib.loads((root / "Cargo.toml").read_text())
        check_manifest(manifest)
        allowed = allowed_packages((root / "PLAN2.md").read_text(), manifest["package"])
        lock = tomllib.loads((root / "Cargo.lock").read_text())
        locked = {(p["name"], p["version"]) for p in lock["package"]}
        for target in args.targets.split(","):
            if target not in {"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "aarch64-apple-darwin"}:
                raise AuditError(f"target outside audited PLAN2 profile: {target}")
            command = ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", target]
            if args.all_features:
                command.append("--all-features")
            p = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=300)
            if p.returncode:
                raise AuditError(p.stderr)
            metadata = json.loads(p.stdout)
            # Metadata can retain optional edges/features that are absent from
            # the build graph (notably webpki's optional ring provider).
            command = ["cargo", "tree", "--locked", "--target", target,
                       "--edges", "normal,build", "--prefix", "none", "--format", "{p}"]
            if args.all_features:
                command.append("--all-features")
            graph = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=300)
            if graph.returncode:
                raise AuditError(graph.stderr)
            selected = set()
            for line in graph.stdout.splitlines():
                match = re.match(r"^([\w-]+) v([^\s]+)(?: |$)", line)
                if not match:
                    raise AuditError(f"unrecognized cargo tree line: {line}")
                selected.add(match.groups())
            packages = [p for p in active_packages(metadata)
                        if (p["name"], p["version"]) in selected]
            if {(p["name"], p["version"]) for p in packages} != selected:
                raise AuditError("active graph and metadata package identities disagree")
            check_packages(packages, allowed)
            active = {(p["name"], p["version"]) for p in packages}
            if not active <= locked:
                raise AuditError("active package missing from lockfile")
            print(f"{target}: {len(active)} active Rust package/version pairs; nine new direct pins; no active native TLS/crypto build")
            inactive = sorted(locked - active)
            print("  inactive lock entries:", ", ".join(f"{n}@{v}" for n, v in inactive) or "none")
        return 0
    except (AuditError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"dependency audit failed: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
