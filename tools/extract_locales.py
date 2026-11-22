#!/usr/bin/env python3
"""Extract gettext strings of the 'iam' domain from PHP and Twig sources into locales/iam.pot.

Usage: python3 tools/extract_locales.py
"""
import glob
import os
import re
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STR = r"'((?:[^'\\]|\\.)*)'"
SINGULAR = re.compile(r"__\(\s*" + STR + r"\s*,\s*'iam'\s*\)")
PLURAL = re.compile(r"_n\(\s*" + STR + r"\s*,\s*" + STR + r"\s*,\s*[^,]+,\s*'iam'\s*\)")


def unescape(s: str) -> str:
    return s.replace("\\'", "'").replace("\\\\", "\\")


def po_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main() -> None:
    entries: dict[tuple, list[str]] = {}
    files = sorted(glob.glob(os.path.join(ROOT, "**", "*.php"), recursive=True)
                   + glob.glob(os.path.join(ROOT, "templates", "*.twig")))
    for path in files:
        if "/vendor/" in path:
            continue
        rel = os.path.relpath(path, ROOT)
        text = open(path, encoding="utf-8").read()
        for rx, kind in ((PLURAL, "p"), (SINGULAR, "s")):
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                key = (unescape(m.group(1)), unescape(m.group(2))) if kind == "p" else (unescape(m.group(1)),)
                entries.setdefault(key, []).append(f"{rel}:{line}")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M+0000")
    out = [
        "# IAM - Identity & Access Governance plugin for GLPI",
        "# This file is distributed under the same license as the plugin (GPL-3.0-or-later).",
        'msgid ""', 'msgstr ""',
        '"Project-Id-Version: iam\\n"', f'"POT-Creation-Date: {now}\\n"',
        '"MIME-Version: 1.0\\n"', '"Content-Type: text/plain; charset=UTF-8\\n"',
        '"Content-Transfer-Encoding: 8bit\\n"', '"Plural-Forms: nplurals=2; plural=(n != 1);\\n"', "",
    ]
    for key, refs in sorted(entries.items(), key=lambda kv: kv[1][0]):
        out.append("#: " + " ".join(refs))
        out.append(f'msgid "{po_escape(key[0])}"')
        if len(key) == 2:
            out.append(f'msgid_plural "{po_escape(key[1])}"')
            out += ['msgstr[0] ""', 'msgstr[1] ""']
        else:
            out.append('msgstr ""')
        out.append("")
    os.makedirs(os.path.join(ROOT, "locales"), exist_ok=True)
    with open(os.path.join(ROOT, "locales", "iam.pot"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    print(f"{len(entries)} strings -> locales/iam.pot")


if __name__ == "__main__":
    main()
