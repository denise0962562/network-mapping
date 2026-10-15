"""Rust embedded inputs must survive the credential-safe Docker context."""
import fnmatch
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class EmbeddedInputsTests(unittest.TestCase):
    def test_open_api_embedded_inputs_are_allowed_and_copied(self):
        rules = [line.strip() for line in (ROOT / '.dockerignore').read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
        stage = (ROOT / 'Dockerfile').read_text().split(' AS rust-builder\n', 1)[1].split('\nFROM ', 1)[0]
        sources = []
        for line in stage.splitlines():
            if line.startswith('COPY ') and '--from=' not in line:
                sources.extend(line.split()[1:-1])

        def included(path):
            result = False
            for rule in rules:
                if fnmatch.fnmatch(path, rule.lstrip('!').rstrip('/')):
                    result = rule.startswith('!')
            return result

        inputs = set()
        for module in (ROOT / 'src/open_api').glob('*.rs'):
            for relative in re.findall(r'include_(?:str|bytes)!\(\s*"([^"]+)"', module.read_text()):
                inputs.add((module.parent / relative).resolve().relative_to(ROOT))
        self.assertTrue(inputs)
        for path in inputs:
            with self.subTest(path=str(path)):
                self.assertTrue((ROOT / path).is_file())
                self.assertTrue(included(path.as_posix()), f'{path} excluded from Docker context')
                self.assertTrue(any(path == Path(source) or Path(source) in path.parents for source in sources),
                                f'{path} missing from rust-builder COPY inputs')
        self.assertFalse(included('docs/credentials.md'))
        self.assertFalse(included('config.toml'))


if __name__ == '__main__':
    unittest.main()
