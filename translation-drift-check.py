#!/usr/bin/env python3
"""Check each translated document against its English source for dropped content.

English is the source of truth; every other locale is translated from it, and
nothing in the Rust suite reads a translation -- `promql_docs_test` opens only
the English `README.md` and `DESIGN.md`. This is the check that closes that gap.

For each heading, the number of lines in that heading's section is compared
against English. A paragraph, bullet or table row that landed in English and
never reached a locale changes that count, which is what makes the comparison
worth more than a whole-file line count.

Run via `make translation-check`. It is a prerequisite of `make lint`, so it
also runs as part of `make test`: exits 0 when every locale matches, 1 otherwise.
"""
import io
import os
import re
import sys

LOCALES = ['zh-TW', 'zh-CN', 'es-ES', 'es-MX', 'ja-JP']
DOCUMENTS = ['CHANGELOG.md', 'DESIGN.md', 'README.md',
             'CONFIGURATION.md', 'CLAUDE.md']


def sections(path):
    """[(heading, body line count)] for a document, ignoring fenced blocks.

    Fence state is tracked line by line rather than with a regex over the whole
    file: prose that mentions ```promql inline would otherwise pair with a real
    fence and swallow every heading between them.
    """
    out, current, count, fence = [], '(preamble)', 0, False
    for line in io.open(path, encoding='utf-8').read().split('\n'):
        if line.startswith('```'):
            fence = not fence
        if not fence and re.match(r'^#{1,4} ', line):
            out.append((current, count))
            current, count = line, 0
        else:
            count += 1
    out.append((current, count))
    return out


def main():
    failures = []
    for base in DOCUMENTS:
        if not os.path.exists(base):
            print(f'{base:26s} SOURCE MISSING')
            failures.append(base)
            continue
        english = sections(base)
        stem = base[:-3]
        for locale in LOCALES:
            path = f'{stem}.{locale}.md'
            if not os.path.exists(path):
                print(f'{path:26s} MISSING')
                failures.append(path)
                continue
            translated = sections(path)
            if len(english) != len(translated):
                print(f'{path:26s} HEADINGS {len(english)} vs '
                      f'{len(translated)}')
                failures.append(path)
                continue
            drift = [(en[0][:42], en[1], tr[1])
                     for en, tr in zip(english, translated) if en[1] != tr[1]]
            if drift:
                detail = '; '.join(f'{h}: {a}/{b}' for h, a, b in drift)
                print(f'{path:26s} {detail}')
                failures.append(path)
            else:
                print(f'{path:26s} OK')

    total = len(DOCUMENTS) * len(LOCALES)
    if failures:
        print(f'\n{len(failures)} of {total} translations differ from English. '
              'Each number pair is English/translation lines for that section.')
        return 1
    print(f'\nAll {total} translations match English.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
