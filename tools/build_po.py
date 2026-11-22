#!/usr/bin/env python3
"""Build locales/<lang>.po from locales/iam.pot and the translation tables below, then compile .mo files.

Requires Babel (pip install babel). Usage: python3 tools/build_po.py
"""
import os
import re
import sys

from babel.messages import pofile, mofile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from translations_es import ES  # noqa: E402

ES_ES: list = []  # (voseo, tuteo) word pairs applied to derive es_ES from es_AR


def build(lang: str, table: dict, replace: list) -> None:
    with open(os.path.join(ROOT, "locales", "iam.pot"), "rb") as fh:
        catalog = pofile.read_po(fh)
    catalog.locale = lang
    catalog.language_team = lang
    missing = []
    for msg in catalog:
        if not msg.id:
            continue
        key = msg.id if isinstance(msg.id, str) else tuple(msg.id)
        value = table.get(key)
        if value is None:
            missing.append(key)
            continue
        if isinstance(value, tuple):
            value = tuple(_apply(v, replace) for v in value)
        else:
            value = _apply(value, replace)
        msg.string = value
    path = os.path.join(ROOT, "locales", f"{lang}.po")
    with open(path, "wb") as fh:
        pofile.write_po(fh, catalog, width=120)
    with open(os.path.join(ROOT, "locales", f"{lang}.mo"), "wb") as fh:
        mofile.write_mo(fh, catalog)
    print(f"{lang}: {len(catalog) - len(missing)} translated, {len(missing)} missing")
    for m in missing:
        print("   MISSING:", m)


def _apply(text: str, replace: list) -> str:
    for a, b in replace:
        text = re.sub(r"\b" + re.escape(a) + r"\b", b, text)
    return text


if __name__ == "__main__":
    build("es_AR", ES, [])
    build("es_ES", ES, ES_ES)
