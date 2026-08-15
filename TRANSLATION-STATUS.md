# Translation status — complete

Snapshot of the doc-translation pass. English is the source of truth; every other
locale is translated from it.

## Locales

Five documents × six locales: `.md` (English), `.zh-TW`, `.zh-CN`, `.es-ES`,
`.es-MX`, `.ja-JP`.

**The Japanese suffix was renamed `.ja` → `.ja-JP`** across all files, nav lines
and `Cargo.toml`. `Cargo.toml`'s `include` list already globs
`/*.es-ES.md`, `/*.es-MX.md`, `/*.ja-JP.md`, so new files need no edit there.

## Done

| Document | zh-TW | zh-CN | es-ES | es-MX | ja-JP |
| -------- | ----- | ----- | ----- | ----- | ----- |
| `CLAUDE` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `CONFIGURATION` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `CHANGELOG` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `DESIGN` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `README` | ✅ | ✅ | ✅ | ✅ | ✅ |

Also completed:

- The Chinese `DESIGN` and `README` were **a release behind** and were resynced:
  the `arpa.` subtree rule, the roots-tier rejection, root-server blame, the
  `dnssec_blamed_roots` metric and the metric family count (77 → 80) were all
  missing.
- All five `CHANGELOG` translations carry the full `Unreleased` section: RBL
  removal, hidden zone cuts, unsigned-child metric, TLS hot-reload, the DoT ALPN
  and SAN fixes, and the new test entries.
- All five `CONFIGURATION` translations carry the TLS-reload material:
  `self_signed_sans`, the no-restart reload paragraph, the runtime-vs-restart
  table row, and the three new troubleshooting rows.
- `README.es-ES.md` was finished (460 → 2176 lines), `README.es-MX.md` derived
  from it, and `README.ja-JP.md` written fresh. All three carry the TLS-reload
  material with the same identifier counts as English.
- The **runtime resolution mode** — `SetResolutionMode` / `GetResolutionMode`,
  the `set-resolution-mode` / `get-resolution-mode` CLI verbs, and "the config
  file is only the startup seed" — is in all six locales of `README`
  (CLI detail sections, gRPC reference sections, the RPC summary row, the Go
  client rows, the config-table row, the *Upstream Resolution* note),
  `CONFIGURATION` (the seed note and the runtime-vs-restart table),
  `DESIGN` (the gRPC and CLI tables) and `CHANGELOG`.
- The **`dot.bind` / `doq.bind` bind-list form** is in all six locales of
  `README` (the bind-syntax section and both config-table rows),
  `CONFIGURATION` (the bind-forms note) and `CHANGELOG`.
- The **`:53` probe loop** (`DnsblChecker::resolver_availability_loop`) is in all
  six locales of `DESIGN` and `CHANGELOG`.

Filling those in also closed three gaps that predated them: the Go client
*Observability* table was missing `SetTrackedTlds` / `ListTrackedTlds` in
`README.zh-CN`, `.zh-TW` and `.ja-JP`, and the gRPC summary table was missing the
same pair in the two Chinese READMEs.

## Verifying

One script lives in the repo root. It is not in `Cargo.toml`'s `include` list —
it checks the tree, it is not shipped to a crate consumer.

```bash
make translation-check                 # the wrapper; use this
python3 translation-drift-check.py     # what it runs, if you want it directly
```

**`translation-check` is a prerequisite of `lint`, so it is part of the gate.**
`make lint` runs it first and `make test` therefore includes it. It exits
non-zero on any drift, naming the section and its English/translation line
counts, so a paragraph that lands in English and never reaches a locale fails
the build rather than sitting unnoticed. This is the check `CLAUDE.md` observed
was missing — nothing else in the suite reads a translation at all.

It adds `python3` to the gate's dependencies, so `make deps` now depends on
`python-deps`, which verifies the interpreter is on PATH and names the package
for the common distributions if it is not. Everything else `deps` provisions
installs rootlessly; a system interpreter cannot, so that target checks rather
than installs. `translation-check` depends on it too, so a missing interpreter
fails with that message instead of a bare `python3: command not found`.

The script itself is pure standard library: no network, no containers, no
third-party packages.

`translation-drift-check.py` reports, per translation, any heading whose section
has a different line count from English — which catches a missing paragraph,
bullet or table row. Run it from the repo root.

**All 25 rows currently report `OK`.** The four that used to be listed here as
cosmetic exceptions are gone: `DESIGN.zh-TW`/`zh-CN` were missing a blank line
between two bullets, and `README.zh-TW`/`zh-CN` wrapped a YAML comment to two
lines where English uses three. Both were reflowed, so every one of the 30
documents is now line-for-line with English rather than merely close to it.

Every document also has heading-for-heading structural parity with English
(same count, same levels, same order) — worth re-checking with the snippet below
after any English edit, since the drift script compares section line counts
rather than the headings themselves.

**CJK paragraphs have to be reflowed to hold this.** Chinese and Japanese pack
far more into a line than English does, so a paragraph translated at a natural
width comes out several lines short and the drift check reports it. New prose in
`.zh-CN`, `.zh-TW` and `.ja-JP` is wrapped to match English's line count for that
paragraph, which is why some line breaks in those files fall in odd places.

Every internal link across all 30 documents resolves — target file exists and,
where a `#fragment` is given, a heading in that file slugs to it. Two of those
are load-bearing and must not be renamed:
`CONFIGURATION.ja-JP.md` links `README.ja-JP.md#設定オプション` and
`README.ja-JP.md#拒否コードとプロバイダーのローテーション`.

Heading-structure parity, which the line-count check does not assert:

```bash
python3 - <<'HEADS'
import io
def h(f): return [l.rstrip().split(' ')[0] for l in io.open(f,encoding='utf-8') if l.startswith('#')]
for doc in ('README','DESIGN','CONFIGURATION','CHANGELOG','CLAUDE'):
    en = h(f'{doc}.md')
    bad = [loc for loc in ('zh-TW','zh-CN','es-ES','es-MX','ja-JP') if h(f'{doc}.{loc}.md') != en]
    print(f"{doc:14} {'ALL MATCH' if not bad else 'DIFFERS: ' + ','.join(bad)}")
HEADS
```

All five documents report `ALL MATCH`: every one of the 30 files has the same
headings, at the same levels, in the same order as English.

To check the PromQL blocks are verbatim (all five report `IDENTICAL`, 32 lines):

```bash
python3 - <<'PY'
import io
def promql(f):
    out=[];on=False
    for l in io.open(f,encoding='utf-8'):
        l=l.rstrip('\n')
        if l.startswith('```promql'): on=True; continue
        if on and l.startswith('```'): on=False; continue
        if on and l.strip() and not l.strip().startswith('#'): out.append(l.strip())
    return out
a=promql('README.md')
for o in ('README.zh-TW.md','README.zh-CN.md','README.es-ES.md','README.es-MX.md','README.ja-JP.md'):
    try: b=promql(o)
    except FileNotFoundError: print(o,'MISSING'); continue
    print(o, len(a), len(b), 'IDENTICAL' if a==b else 'DIFFERS')
PY
```

## es-MX is hand-maintained

**There is no generator.** es-MX was bootstrapped by deriving it from es-ES with
a substitution script, and that script has been deleted: it got the files to
line-for-line parity and then stopped earning its keep. Edit `*.es-MX.md`
directly, the same way as every other locale.

The bootstrap is worth recording, because the reasons it was retired are the
reasons not to write another one. Word-level substitution does not know what the
words mean, and each of these was a bug it shipped before being caught:

- **`enlace` carries five senses here** — a bind, a network link, a symlink,
  language bindings and an HTML link — and only the first is `ligadura`. The
  first derivation converted all of them and produced *"un ligadura simbólico"*
  for a symlink.
- **`palabra clave`** (keyword) became *"palabra llave"*.
- **`peticiones entre sitios`** (cross-site, i.e. CSRF) became *"entre lugares"*.
- **`la caché` → `el caché` changes gender**, dragging the contractions
  (`de la` → `del`, `a la` → `al`) and any following adjective with it.
- **Converting a heading breaks every `](#…)` aimed at it**, which silently
  shipped two dead anchors in `CONFIGURATION.es-MX.md`.
- **Spanish conjugation outruns any hand-written list of forms**
  (`comprobaba`, `comprobarse`, `comprobando`, `comprobaron`, …).
- **Backtick masking is harder than it looks.** A line with an odd number of
  backticks mis-pairs a naive `` `[^`]*` `` matcher, and an inline ` ```promql `
  mention pairs with the next one as though it opened a code span — both swallow
  real prose, and both bite hardest in the documentation sections whose subject
  *is* fenced blocks.
- **`YYYYMMDDHHmmSS`** is the RFC 4034 zone-file presentation format, named
  verbatim in `src/dnssec.rs`, and must not be localized to `AAAAMMDDHHmmSS`.

What actually protects the invariant is `translation-drift-check.py`, which is
independent of how the files get written.

The lexicon still applies when editing es-MX by hand:

| es-ES | es-MX |
| ----- | ----- |
| fichero(s) | archivo(s) |
| por defecto | por omisión |
| resolutor | resolvedor |
| añadir / añade | agregar / agrega |
| enlazar / enlace | ligar / ligadura |
| gestionar / gestión / gestor | administrar / administración / administrador |
| comprobar / comprobación | revisar / revisión |
| sitio(s) | lugar(es) |
| utilizable | usable |
| doméstico | casero |
| accesible | alcanzable |
| unos pocos | unos cuantos |
| tras | después de |
| frente a | contra |
| tabla de rutas | tabla de ruteo |
| nombre de máquina | nombre de host |
| la caché | el caché |
| clave (crypto) | llave |
| cazar | cachar |
| vigilar | monitorear |

`clave` → `llave` is applied throughout, in all five documents. (The corpus was
briefly inconsistent on this — `DESIGN.es-MX.md` alone kept `clave` — and no
longer is.)

## Two leftovers from the RBL removal, now fixed

Both were flagged in an earlier pass as English-source defects and have since
been corrected in English and carried into all five locales:

1. **The Go client *Forwarding & Blocklists* table** carried a corrupted row —
   `|@@DROP@@ctx, enabled, providers, secs)\` | The same, with the list-wide …` —
   the residue of a half-applied edit removing `SetRblConfigWithRefusalCooldown`.
   It now reads as `SetDnsblConfigWithRefusalCooldown`.
2. **The CLI table** described `set-dnsbl-config` as taking the "same flags as
   `set-rbl-config`", a command that no longer exists. It now lists the real
   flags: `--enabled`, `--providers`, `--refusal-codes`, `--provider-cooldown`
   and `--refusal-cooldown`.

## Checks the drift script cannot make

Line counts and heading structure can match while the *content* has drifted, and
two such gaps were found and fixed this way:

- **A stale count.** `README` claimed the service defines 77 RPC methods;
  `proto/rolodex_dns.proto` declares 74. Three locales still said 77 after
  English was corrected. Compare a documented count against the thing it counts,
  not against the other translations.
- **A missing identifier.** Comparing the multiset of code identifiers in
  `` `backticks` `` between English and each locale catches a translation that
  dropped or localized one. Placeholders (`ip:puerto`, `interfaz:puerto`,
  `ip:ポート`) are localized on purpose and will show up as differences; real
  identifiers must not be. Order is not meaningful — translations reorder
  clauses freely — so compare as a multiset.

## Note on the moving target

Every translation here is synced against English as of this pass. English is
still the only file anything verifies — `tests/promql_docs_test.rs` reads only
`README.md` and `DESIGN.md` — so re-run `translation-drift-check.py` after any
English edit rather than assuming a locale is current.
