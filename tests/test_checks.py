from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from picarx_security_baseline.checks import run_checks
from picarx_security_baseline.report import render_markdown


class SecurityBaselineTests(unittest.TestCase):
    def test_secure_fixture_reports_expected_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc" / "os-release", 'PRETTY_NAME="Raspberry Pi OS"\n')
            write(root / "etc" / "hostname", "picarx-lab-01\n")
            write(root / "etc" / "passwd", "instructor:x:1000:1000::/home/instructor:/bin/bash\n")
            write(
                root / "etc" / "ssh" / "sshd_config",
                "PasswordAuthentication no\nPermitRootLogin no\n",
            )
            write(root / "etc" / "sudoers", "%sudo ALL=(ALL:ALL) ALL\n")
            write(root / "usr" / "sbin" / "ufw", "")

            findings = {finding.check_id: finding for finding in run_checks(root)}

            self.assertEqual(findings["ID-001"].status, "pass")
            self.assertEqual(findings["AC-001"].status, "pass")
            self.assertEqual(findings["SSH-001"].status, "pass")
            self.assertEqual(findings["SSH-002"].status, "pass")
            self.assertEqual(findings["AC-002"].status, "pass")

    def test_insecure_fixture_reports_actionable_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc" / "hostname", "raspberrypi\n")
            write(root / "etc" / "passwd", "pi:x:1000:1000::/home/pi:/bin/bash\n")
            write(
                root / "etc" / "ssh" / "sshd_config",
                "PasswordAuthentication yes\nPermitRootLogin yes\n",
            )
            write(root / "etc" / "sudoers.d" / "010_pi", "pi ALL=(ALL) NOPASSWD: ALL\n")

            findings = {finding.check_id: finding for finding in run_checks(root)}

            self.assertEqual(findings["ID-001"].status, "fail")
            self.assertEqual(findings["AC-001"].status, "warn")
            self.assertEqual(findings["SSH-001"].status, "fail")
            self.assertEqual(findings["SSH-002"].status, "warn")
            self.assertEqual(findings["AC-002"].status, "warn")

    def test_markdown_report_escapes_table_cells(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc" / "os-release", 'PRETTY_NAME="A | B"\n')
            report = render_markdown(run_checks(root))
            self.assertIn("A \\| B", report)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
