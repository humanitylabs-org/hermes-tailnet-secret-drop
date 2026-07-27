import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROMPT_FILE = ROOT / "docs" / "give-this-prompt-to-your-ai.md"


class DocumentationTests(unittest.TestCase):
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
