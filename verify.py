"""Run reference tests and all fixed synthetic examples without network access."""
import argparse
import importlib.metadata
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
SUITES = (
    ('bx-seed', 'test_reference.py'),
    ('armory-feedback', 'test_recover.py'),
    ('shared', 'test_references.py'),
    ('small-prng', 'test_recovery.py'),
    ('xorshift128', 'test_recovery.py'),
    ('masking-feedback', 'test_feedback.py'),
    ('mwc1616', 'test_recovery.py'),
    ('mwc1616/direct', 'test_direct.py'),
    ('dotnet-random', 'test_screen.py'),
    ('dotnet-random', 'test_exact.py'),
    ('dotnet-seed', 'test_recovery.py'),
    ('bitcoinjs-arc4', 'test_pipeline.py'),
    ('bitcoinjs-arc4', 'test_recovery.py'),
    ('bx-seed', 'test_recovery.py'),
)
METHODS = ('small-prng', 'xorshift128', 'mwc1616', 'mwc1616/direct',
           'bitcoinjs-arc4', 'bx-seed', 'dotnet-random', 'dotnet-seed',
           'masking-feedback', 'armory-feedback', 'masked-xpub')


def command(arguments):
    process = subprocess.run([sys.executable, '-B', *arguments], cwd=ROOT,
                             text=True, capture_output=True)
    if process.returncode:
        sys.stdout.write(process.stdout)
        sys.stderr.write(process.stderr)
        raise SystemExit(process.returncode)
    return process


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, help='Write the verification results as JSON')
    args = parser.parse_args()
    suites = []
    for directory, pattern in SUITES:
        result = command(['-m', 'unittest', 'discover', '-s', str(ROOT / directory), '-p', pattern])
        count = re.search(r'Ran (\d+) tests?', result.stderr)
        if not count or 'OK' not in result.stderr or 'skipped=' in result.stderr:
            raise RuntimeError('Suite did not complete all expected checks: ' + directory)
        suites.append({'method': directory, 'suite': pattern, 'tests': int(count[1]), 'passed': True})
        print(f'{directory}/{pattern}: {count[1]} tests passed', flush=True)
    examples = {}
    for directory in METHODS:
        result = command([str(ROOT / directory / 'example.py')])
        examples[directory] = json.loads(result.stdout)
        print(f'{directory}/example.py: passed', flush=True)
    with tempfile.TemporaryDirectory(prefix='scalar-research-') as directory:
        result = command([str(ROOT / 'masked-xpub/synthetic_analysis.py'),
                          '--wallet-count', '4', '--output', str(Path(directory) / 'constraints.json')])
        constraints = json.loads(result.stdout)
        if not constraints['tests_passed']:
            raise RuntimeError('Scalar constraint analysis did not pass')
    report = {
        'python': sys.version.split()[0],
        'dependencies': {name: importlib.metadata.version(name)
                         for name in ('cryptography', 'z3-solver')},
        'tests_passed': sum(s['tests'] for s in suites),
        'suites': suites,
        'examples': examples,
        'scalar_constraint_analysis_passed': True,
    }
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'tests_passed': report['tests_passed'],
                      'example_count': len(examples),
                      'scalar_constraint_analysis_passed': True}, indent=2))


if __name__ == '__main__':
    main()
