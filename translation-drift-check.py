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
             'CONFIGURATION.md', 'CLAUDE.md', 'TOWNOS_CONTRACT.md']


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


# A code identifier is a thing the software actually answers to -- a config key,
# an RPC or type name, a metric, a CLI flag, a source file. Those must survive
# translation verbatim. Placeholders that describe a shape rather than name a
# thing (`ip:port` -> `ip:puerto`, `host:port` -> `ip:ポート`) are localized on
# purpose and must not match here, which is why this is a narrow allowlist of
# shapes rather than "everything in backticks".
CODE_SPAN = re.compile(r'`([^`\n]+)`')
CODE_IDENT = re.compile(r"""^(?:
      [a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+   # config keys: dns.auto_ptr
    | [A-Z][A-Za-z0-9]{3,}               # RPC and type names: SetResolutionMode
    | rolodex_dns_[a-z0-9_]+             # metric families
    | --[a-z][a-z-]+                     # CLI flags: --refusal-codes
    | [a-z][a-z0-9_-]*\.rs               # source files
    | tests/[\w.]+                       # test paths
    )$""", re.VERBOSE)


def identifiers(path):
    """Multiset of code identifiers a document names."""
    from collections import Counter
    text = io.open(path, encoding='utf-8').read()
    return Counter(s for s in CODE_SPAN.findall(text) if CODE_IDENT.match(s))


def check_identifiers(base, path):
    """Identifiers English names that the translation does not, and how often.

    Order is not compared: translations reorder clauses freely, and a sequence
    comparison drowns in that. What matters is that nothing was dropped or
    localized away -- the failure mode where a locale silently loses the one
    config key a section exists to document.
    """
    english, translated = identifiers(base), identifiers(path)
    return {name: (n, translated.get(name, 0))
            for name, n in english.items() if translated.get(name, 0) < n}


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
                continue
            missing = check_identifiers(base, path)
            if missing:
                detail = '; '.join(f'`{n}` {a}/{b}'
                                   for n, (a, b) in sorted(missing.items()))
                print(f'{path:26s} IDENTIFIERS {detail}')
                failures.append(path)
            else:
                print(f'{path:26s} OK')

    total = len(DOCUMENTS) * len(LOCALES)
    if failures:
        print(f'\n{len(failures)} of {total} translations differ from English.\n'
              '  section rows      number pair is English/translation lines\n'
              '  IDENTIFIERS rows  number pair is how often English names it '
              'vs the translation')
        return 1
    print(f'\nAll {total} translations match English.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
