# Bazarish project (c) 2026
import json
import re
import sys
from pathlib import Path

LANGUAGES = ["ru", "es", "zh", "ar"]
LITERAL = r'"(?:[^"\\]|\\.)*"'
# A long text is written as literals joined with + over several lines; the catalog knows the whole.
JOINED = LITERAL + r'(?:\s*\+\s*' + LITERAL + r')*'
USES = [re.compile(r'\b(?:t|N_)\(\s*(' + JOINED + r')')]
MARKED = re.compile(r'data-t="([^"]*)"')
PLACEHOLDER = re.compile(r"%\d")


def used(web):
    keys = set()
    for path in web.glob("*.js"):
        if path.name == "messages.js":
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in USES:
            for match in pattern.finditer(text):
                keys.add("".join(json.loads(part)
                    for part in re.findall(LITERAL, match.group(1))))
    for path in web.glob("*.html"):
        for match in MARKED.finditer(path.read_text(encoding="utf-8")):
            keys.add(match.group(1).replace("&amp;", "&"))
    return keys


def catalog(web):
    text = (web / "messages.js").read_text(encoding="utf-8")
    start = text.index("{")
    return json.loads(text[start:text.rindex("}") + 1])


def main():
    web = Path(sys.argv[1])
    keys = used(web)
    messages = catalog(web)
    problems = []
    for language in LANGUAGES:
        table = messages.get(language, {})
        for key in sorted(keys):
            if key not in table or not table[key]:
                problems.append(f"{language}: missing {key!r}")
            elif sorted(PLACEHOLDER.findall(key)) != sorted(PLACEHOLDER.findall(table[key])):
                problems.append(f"{language}: placeholders differ in {key!r}")
        for key in sorted(set(table) - keys):
            problems.append(f"{language}: orphan {key!r}")
    for problem in problems:
        print(problem)
    print(f"{len(keys)} strings, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
