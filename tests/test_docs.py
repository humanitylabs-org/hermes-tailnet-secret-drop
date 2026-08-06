import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROMPT_FILE = ROOT / "docs" / "give-this-prompt-to-your-ai.md"
DOC_FILES = (
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    ROOT / "skill" / "SKILL.md",
    PROMPT_FILE,
)


class DocumentationTests(unittest.TestCase):
    def test_documentation_never_presents_the_removed_token_route_as_current(self):
        # The route may still be named while explaining that it is gone, but no
        # document may describe it as a route the service still serves.
        for path in DOC_FILES:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if "/r/" not in line:
                    continue
                with self.subTest(path=path.name, line=number):
                    self.assertIn("removed", line.casefold())

    def test_documentation_keeps_opaque_validation_honest(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        skill = (ROOT / "skill" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Syntax only", readme)
        self.assertIn("does **not** contact any provider", readme)
        self.assertIn("Provider validation is available only through an adapter", readme)
        self.assertIn("it contacts no provider", skill)

    def test_documentation_explains_the_fragment_capability(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("#token=", readme)
        self.assertIn("history.replaceState", readme)
        self.assertIn("X-Secret-Drop-Token", readme)
        self.assertIn("X-Secret-Drop-Token", security)
        self.assertIn("SHA-256(capability)", security)
        self.assertIn("Origin", security)

    def test_copy_prompt_fits_one_telegram_message_with_headroom(self):
        text = PROMPT_FILE.read_text(encoding="utf-8")
        prompt = text.split("```text\n", 1)[1].split("\n```", 1)[0]
        self.assertLessEqual(len(prompt), 3000)
        for required in (
            "Tailscale is mandatory",
            "Ask before running that command, sudo, or any package-manager action",
            "Never enable Funnel",
            "hermes-secret-drop demo",
            "expire within 15 minutes",
            "discarded",
            "active link is gone",
        ):
            with self.subTest(required=required):
                self.assertIn(required, prompt)


if __name__ == "__main__":
    unittest.main()
