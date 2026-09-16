"""S01 independent malformed-input fixtures for the local audit tools."""
import copy
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import conformance_audit as ca
import dependency_audit as da


class LedgerTests(unittest.TestCase):
    def fixture(self, root):
        (root / "tests").mkdir()
        (root / "src").mkdir()
        (root / "tests/sample.rs").write_text("#[test]\nfn closes_requirement() { assert_eq!(1, 1); }\n")
        (root / "src/lib.rs").write_text("pub fn implemented() {}\n")
        draft = "Router MUST work.\nRouter SHOULD recover.\n"
        plan = ("| R001 | 1 | 1 | MUST work | DONE |\n"
                "| R002 | 2 | 2 | SHOULD recover | TODO |\n")
        rows = [dict(id="R001", status="DONE", code="src/lib.rs:1", tests="tests/sample.rs::closes_requirement", closure="S01"),
                dict(id="R002", status="TODO", code="", tests="", closure="S02")]
        return draft, plan, rows

    def test_provisional_and_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            draft, plan, rows = self.fixture(root)
            ca.audit(draft, plan, rows, root, complete=False, expected_ids={"R001", "R002"})
            with self.assertRaises(ca.AuditError):
                ca.audit(draft, plan, rows, root, complete=True, expected_ids={"R001", "R002"})
            rows[1] = dict(rows[0], id="R002")
            ca.audit(draft, plan, rows, root, complete=True, expected_ids={"R001", "R002"})

    def test_dropped_duplicate_unknown_keyword_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            draft, plan, rows = self.fixture(root)
            for bad in [plan.replace("| 2 | 2 |", "| 2 | 1 |"),
                        plan.splitlines()[0], plan + plan.splitlines()[0],
                        plan.replace("R002", "R999")]:
                with self.subTest(plan=bad), self.assertRaises(ca.AuditError):
                    ca.audit(draft, bad, rows, root, expected_ids={"R001", "R002"})

    def test_matrix_evidence_and_ignored_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            draft, plan, rows = self.fixture(root)
            mutations = [dict(id="R999"), dict(code="src/absent.rs:1"), dict(code="src/lib.rs:99"),
                         dict(tests="tests/sample.rs::absent"), dict(tests=""), dict(status="BANANA"),
                         dict(closure=""), dict(code="../escape.rs:1")]
            for changes in mutations:
                bad = [dict(rows[0], **changes), rows[1]]
                with self.subTest(changes=changes), self.assertRaises(ca.AuditError):
                    ca.audit(draft, plan, bad, root, expected_ids={"R001", "R002"})
            for bad in [rows[:1], rows + rows[:1]]:
                with self.assertRaises(ca.AuditError):
                    ca.audit(draft, plan, bad, root, expected_ids={"R001", "R002"})
            for attrs in ["#[ignore]", '#[ignore = "unfinished"]', "#[cfg_attr(all(), ignore)]"]:
                (root / "tests/sample.rs").write_text(f"#[test]\n{attrs}\nfn closes_requirement() {{}}\n")
                with self.subTest(attrs=attrs), self.assertRaises(ca.AuditError):
                    ca.audit(draft, plan, rows, root, expected_ids={"R001", "R002"})

    def test_complete_rejects_missing_partial_and_omitted_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            draft, plan, rows = self.fixture(root)
            rows[1] = dict(rows[0], id="R002")
            for status in ["MISSING", "PARTIAL"]:
                bad = [rows[0], dict(rows[1], status=status)]
                with self.subTest(status=status), self.assertRaises(ca.AuditError):
                    ca.audit(draft, plan, bad, root, complete=True, expected_ids={"R001", "R002"})
            with self.assertRaises(ca.AuditError):
                ca.audit(draft, plan, rows[:1], root, complete=True, expected_ids={"R001", "R002"})
            (root / "tests/sample.rs").write_text("// deliberately deleted closure test\n")
            with self.assertRaises(ca.AuditError):
                ca.audit(draft, plan, rows, root, complete=True, expected_ids={"R001", "R002"})

    def test_repository_complete_inventory(self):
        args = [sys.executable, str(ROOT / "scripts/conformance_audit.py")]
        p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("103", p.stdout)
        self.assertIn("112", p.stdout)
        p = subprocess.run(args + ["--require-complete"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        p = subprocess.run(args + ["--matrix", "REVIEW.md", "--require-complete"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


class DependencyTests(unittest.TestCase):
    def test_normal_build_edges_and_inactive_dev(self):
        m = {"packages": [{"id": n, "name": n, "version": "1.0.0", "links": None} for n in ["root", "normal", "build", "ring"]],
             "resolve": {"root": "root", "nodes": [
                 {"id": "root", "deps": [
                     {"pkg": "normal", "dep_kinds": [{"kind": None}]},
                     {"pkg": "build", "dep_kinds": [{"kind": "build"}]},
                     {"pkg": "ring", "dep_kinds": [{"kind": "dev"}]}]},
                 *[{"id": n, "deps": []} for n in ["normal", "build", "ring"]]]}}
        active = da.active_packages(m)
        self.assertEqual({p["name"] for p in active}, {"root", "normal", "build"})
        allowed = {(p["name"], p["version"]) for p in active}
        da.check_packages(active, allowed)
        for name, links in [("ring", None), ("aws-lc-sys", None), ("native-tls", None), ("cc", None), ("normal", "ssl")]:
            with self.subTest(name=name), self.assertRaises(da.AuditError):
                da.check_packages([{"name": name, "version": "1.0.0", "links": links}], allowed | {(name, "1.0.0")})
        with self.assertRaises(da.AuditError):
            da.check_packages([{"name": "normal", "version": "1.0.1", "links": None}], allowed)

    def test_direct_pins_features_and_policy(self):
        import tomllib
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        da.check_manifest(manifest)
        for change in [lambda m: m["dependencies"].update({"unlisted": "=1.0.0"}),
                       lambda m: m["dependencies"]["rustls"].update({"default-features": True}),
                       lambda m: m["dependencies"]["rustls"].update({"version": "0.23.45"}),
                       lambda m: m.update({"build-dependencies": {"cc": "=1.0.0"}}),
                       lambda m: m["dependencies"]["smoltcp"]["features"].append("medium-ethernet")]:
            bad = copy.deepcopy(manifest)
            change(bad)
            with self.assertRaises(da.AuditError):
                da.check_manifest(bad)


if __name__ == "__main__":
    unittest.main()
