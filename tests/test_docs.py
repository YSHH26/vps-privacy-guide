"""Keep public teaching links and examples safe to copy."""
from pathlib import Path
import re
import unittest
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]


class DocsTests(unittest.TestCase):
    def test_markdown_relative_links_exist(self):
        paths=[ROOT/'README.md',ROOT/'AGENTS.md',*sorted((ROOT/'docs').rglob('*.md'))]
        for path in paths:
            for href in re.findall(r'\]\(([^)]+)\)',path.read_text()):
                parsed=urllib.parse.urlsplit(href)
                if parsed.scheme or href.startswith('#'):continue
                target=urllib.parse.unquote(parsed.path)
                if target:
                    with self.subTest(file=str(path.relative_to(ROOT)),link=href):
                        self.assertTrue((path.parent/target).exists())

    def test_public_examples_use_reserved_ipv4_only(self):
        paths=[ROOT/'README.md',ROOT/'AGENTS.md',*sorted((ROOT/'docs').rglob('*.md')),
               *sorted((ROOT/'examples').glob('*.json'))]
        for path in paths:
            for value in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',path.read_text()):
                with self.subTest(file=str(path.relative_to(ROOT)),address=value):
                    self.assertTrue(value in {'0.0.0.0','127.0.0.1','1.1.1.1'} or
                                    value.startswith(('192.0.2.','198.51.100.','203.0.113.')))


if __name__=='__main__':unittest.main()
