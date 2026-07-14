#!/usr/bin/env python3
"""Regression tests for qualification-script secret transport."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_SCRIPT = ROOT / "scripts" / "qualify-runtime-database.sh"
RESTORE_SCRIPT = ROOT / "scripts" / "qualify-logical-backup-restore.sh"


class QualificationSecretTransportTests(unittest.TestCase):
    def test_request_secrets_are_absent_from_curl_argv(self) -> None:
        source = RUNTIME_SCRIPT.read_text(encoding="utf-8")
        start = source.index("request_json() {")
        end = source.index("\njson_field() {", start)
        request_function = source[start:end]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            capture = root / "capture.json"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                """#!/usr/bin/env python3
import json
import os
import stat
import sys
from pathlib import Path

arguments = sys.argv[1:]
output = Path(arguments[arguments.index("--output") + 1])
config = Path(arguments[arguments.index("--config") + 1])
body_argument = arguments[arguments.index("--data-binary") + 1]
body = Path(body_argument[1:])
token = os.environ["SECRET_TOKEN"]
payload = os.environ["SECRET_BODY"]
Path(os.environ["CAPTURE_PATH"]).write_text(json.dumps({
    "arguments": arguments,
    "token_in_config": token in config.read_text(encoding="utf-8"),
    "body_matches": body.read_text(encoding="utf-8") == payload,
    "config_mode": stat.S_IMODE(config.stat().st_mode),
    "body_mode": stat.S_IMODE(body.stat().st_mode),
}), encoding="utf-8")
output.write_text('{"ok":true}', encoding="utf-8")
print("200", end="")
""",
                encoding="utf-8",
            )
            fake_curl.chmod(0o755)
            harness = root / "harness.sh"
            harness.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                f"runtime_dir={str(root)!r}\n"
                "AUTHOS_URL=http://127.0.0.1:1\n"
                f"{request_function}\n"
                'request_json POST /secret 200 "$SECRET_BODY" "$SECRET_TOKEN" >/dev/null\n',
                encoding="utf-8",
            )

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "CAPTURE_PATH": str(capture),
                    "SECRET_TOKEN": "secret-token-canary",
                    "SECRET_BODY": '{"password":"secret-password-canary"}',
                }
            )
            subprocess.run(["bash", str(harness)], env=environment, check=True)

            evidence = json.loads(capture.read_text(encoding="utf-8"))
            argv = "\0".join(evidence["arguments"])
            self.assertNotIn(environment["SECRET_TOKEN"], argv)
            self.assertNotIn(environment["SECRET_BODY"], argv)
            self.assertNotIn("secret-password-canary", argv)
            self.assertTrue(evidence["token_in_config"])
            self.assertTrue(evidence["body_matches"])
            self.assertEqual(evidence["config_mode"], 0o600)
            self.assertEqual(evidence["body_mode"], 0o600)
            self.assertEqual(list(root.glob("curl-config.*")), [])
            self.assertEqual(list(root.glob("request-body.*")), [])

    def test_python_parsers_take_credentials_from_stdin(self) -> None:
        runtime = RUNTIME_SCRIPT.read_text(encoding="utf-8")
        restore = RESTORE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("printf '%s\\0%s'", runtime)
        self.assertNotIn(
            '\"$AUTHOS_OWNER_EMAIL\" \"$AUTHOS_OWNER_PASSWORD\")', runtime
        )
        self.assertIn("urlparse(sys.stdin.read())", restore)
        self.assertNotIn('python3 - "$database_url"', restore)

    def test_qualification_scripts_have_valid_shell_syntax(self) -> None:
        for script in (RUNTIME_SCRIPT, RESTORE_SCRIPT):
            subprocess.run(["bash", "-n", str(script)], check=True)


if __name__ == "__main__":
    unittest.main()
