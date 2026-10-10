"""The WRN literal check (INT-B3: "A linter rule refuses building WRN strings
outside that library").

It reads every `.py` file under the paths given and reports each string,
bytes or f-string literal whose text begins with `wrn:`: a hard-coded WRN, or
the start of one being built by `+`, `%`, `.format` or an f-string. Build
WRNs with `Wrn(service, type, id)` / `Wrn.new(...)` and read them with
`parse_wrn`; `str(w)` is the only formatter. Prose that merely mentions
`wrn:` mid-sentence, comments and other file types are not read.

Escape hatch: put the comment `# wrn-ok` (optionally with a reason,
`# wrn-ok: test fixture`) on any line of the statement holding the literal.
It is per statement and greppable; `--exclude` takes glob patterns for whole
paths (matched against the path relative to the argument and the absolute
path), for example a test-fixture directory.

Run it in CI:

    wolf-access-wrn-lint src/ --exclude 'tests/fixtures/*'
    python -m wolf_access_client.wrn_lint src/

Exit status: 0 clean, 1 a literal (or a file that is not valid Python) was
found, 2 a path does not exist. Call `find_wrn_literals` to use it from a test.
"""

from __future__ import annotations

import argparse
import ast
import io
import sys
import tokenize
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, Iterator, Sequence

__all__ = ["ALLOW_COMMENT", "WrnLiteral", "find_wrn_literals", "main"]

#: The comment that lets one statement's WRN literal through.
ALLOW_COMMENT = "# wrn-ok"
_PREFIX = "wrn" + ":"
_SKIP_DIRS = frozenset({"__pycache__", "node_modules", "site-packages"})
_LITERAL = (f"a WRN built from a string literal; use Wrn(service, type, id) or parse_wrn "
            f"(INT-B3), or mark the statement '{ALLOW_COMMENT}'")


@dataclass(frozen=True)
class WrnLiteral:
    """One finding: where, and what is wrong."""

    path: Path
    line: int
    column: int
    problem: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column}: {self.problem}"


def _starts_a_wrn(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        first = node.values[0] if node.values else None
        return isinstance(first, ast.Constant) and _starts_a_wrn(first)
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, str):
            return value.startswith(_PREFIX)
        if isinstance(value, bytes):
            return value.startswith(_PREFIX.encode())
    return False


def _allowed_lines(source: str) -> set[int]:
    lines: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT and tok.string.startswith(ALLOW_COMMENT):
                lines.add(tok.start[0])
    except (tokenize.TokenError, SyntaxError):
        pass
    return lines


def _literals(tree: ast.AST) -> Iterator[tuple[ast.AST, ast.stmt | None]]:
    """Every literal that starts a WRN, with its innermost statement. A
    constant inside an f-string is judged as part of the f-string."""

    def visit(node: ast.AST, stmt: ast.stmt | None) -> Iterator[tuple[ast.AST, ast.stmt | None]]:
        if isinstance(node, ast.stmt):
            stmt = node
        if isinstance(node, (ast.JoinedStr, ast.Constant)):
            if _starts_a_wrn(node):
                yield node, stmt
            if isinstance(node, ast.JoinedStr):
                for value in node.values:   # format specs may hold f-strings of their own
                    if isinstance(value, ast.FormattedValue):
                        yield from visit(value, stmt)
                return
        for child in ast.iter_child_nodes(node):
            yield from visit(child, stmt)

    yield from visit(tree, None)


def _check_file(path: Path) -> list[WrnLiteral]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return [WrnLiteral(path, 1, 0, "not valid Python")]
    allowed = _allowed_lines(source)
    found = []
    for node, stmt in _literals(tree):
        span = stmt if stmt is not None else node
        first, last = span.lineno, getattr(span, "end_lineno", None) or span.lineno
        if any(first <= line <= last for line in allowed):
            continue
        found.append(WrnLiteral(path, node.lineno, node.col_offset, _LITERAL))
    return found


def _excluded(path: Path, root: Path, exclude: Sequence[str]) -> bool:
    candidates = [path.as_posix(), path.resolve().as_posix()]
    try:
        candidates.append(path.relative_to(root).as_posix())
    except ValueError:
        pass
    return any(fnmatch(c, pattern) for c in candidates for pattern in exclude)


def _python_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root).parts[:-1]
        if any(p.startswith(".") or p in _SKIP_DIRS or p.endswith(".egg-info")
               for p in parts):
            continue
        yield path


def find_wrn_literals(paths: Iterable[str | Path], *,
                      exclude: Sequence[str] = ()) -> list[WrnLiteral]:
    """Every WRN literal in the `.py` files under `paths` (files or
    directories), in path and line order. A path that does not exist raises
    `FileNotFoundError`."""
    found: list[WrnLiteral] = []
    for raw in paths:
        root = Path(raw)
        if not root.exists():
            raise FileNotFoundError(str(root))
        for path in _python_files(root):
            if not _excluded(path, root, exclude):
                found.extend(_check_file(path))
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wolf-access-wrn-lint",
        description="Refuse WRN string literals outside wolf_access_client.wrn (INT-B3).")
    parser.add_argument("paths", nargs="*", default=["."], help="files or directories")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="skip paths matching GLOB (repeatable)")
    args = parser.parse_args(argv)
    try:
        found = find_wrn_literals(args.paths, exclude=args.exclude)
    except FileNotFoundError as exc:
        print(f"wolf-access-wrn-lint: no such path: {exc}", file=sys.stderr)
        return 2
    for finding in found:
        print(finding)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
