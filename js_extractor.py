#!/usr/bin/env python3
"""
js_extractor.py - Static extraction of functions, comments and variables
from JavaScript / HTML files.

Every input file is a "Page" (file 1 = page 1, file 2 = page 2, ...).
Every function found (nested ones included) is written to its own file:

    <page>.<index>_<functionName>.js      e.g.  1.1_login.js, 1.2_anonymous.js

Extra outputs in the output directory:
    numbering_map.json   page -> source file -> function id -> name -> output file
    comments.txt         all comments, tagged by page and source file
    variables.txt        all var/let/const declarations, grouped by page
    errors.log           files / script blocks that could not be parsed
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import esprima
from bs4 import BeautifulSoup

try:
    import jsbeautifier
except Exception:  # pragma: no cover
    jsbeautifier = None

JS_EXT = {".js", ".mjs", ".cjs"}
HTML_EXT = {".html", ".htm"}
FUNC_TYPES = {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}
CLASS_TYPES = {"ClassDeclaration", "ClassExpression"}
JS_SCRIPT_TYPES = {
    "", "module", "text/javascript", "application/javascript",
    "application/x-javascript", "text/ecmascript", "application/ecmascript",
}
SKIP_KEYS = {"type", "range", "loc"}

log = logging.getLogger("js_extractor")
sys.setrecursionlimit(20000)


# --------------------------------------------------------------------------
# Data containers
# --------------------------------------------------------------------------
@dataclass
class FuncRecord:
    name: str
    kind: str
    text: str
    start: int          # absolute char offset in its chunk (for ordering)
    chunk: int          # chunk number (HTML may have several <script> blocks)
    start_line: int
    end_line: int
    func_id: str = ""
    out_file: str = ""


@dataclass
class PageResult:
    page: int
    source: str
    source_type: str
    status: str = "ok"                  # ok | partial | error
    errors: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    comments: list = field(default_factory=list)    # (line, kind, text)
    variables: list = field(default_factory=list)   # dicts


# --------------------------------------------------------------------------
# Reading / input handling
# --------------------------------------------------------------------------
def read_text(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def natural_key(p: Path):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", p.name)]


def collect_files(root: Path, recursive: bool):
    pattern = "**/*" if recursive else "*"
    files = [p for p in root.glob(pattern)
             if p.is_file() and p.suffix.lower() in JS_EXT | HTML_EXT]
    return sorted(files, key=lambda p: (str(p.parent).lower(), natural_key(p)))


def html_script_chunks(src: str):
    """Yield (code, line_offset) for each inline <script> in an HTML document."""
    soup = BeautifulSoup(src, "html.parser")
    for tag in soup.find_all("script"):
        stype = (tag.get("type") or "").strip().lower()
        if stype not in JS_SCRIPT_TYPES:
            continue                      # json, templates, etc.
        code = tag.string if tag.string is not None else tag.get_text()
        if not code or not code.strip():
            continue                      # external <script src=...> only
        # html.parser reports the line of the opening tag; code starts there
        offset = (tag.sourceline or 1) - 1
        yield code, offset


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------
def normalize_minified_js(code: str) -> str:
    """Convert one-line bundle output into readable multi-line JS before parsing."""
    if not code or "\n" in code or "\r" in code:
        return code
    stripped = code.strip()
    if len(stripped) < 300:
        return stripped

    if jsbeautifier is not None:
        try:
            options = jsbeautifier.default_options()
            options.indent_size = 2
            options.space_in_paren = True
            options.keep_array_indentation = False
            return jsbeautifier.beautify(stripped, options)
        except Exception:
            pass

    result = re.sub(r"([;{}])", r"\1\n", stripped)
    result = re.sub(r"\n\s*\n+", "\n", result)
    return result


def parse_js(code: str):
    """Try script mode, then module mode (import/export)."""
    code = normalize_minified_js(code)
    shebang = code.startswith("#!")
    if shebang:                           # shebang -> comment, offsets unchanged
        code = "//" + code[2:]
    opts = {"range": True, "loc": True, "comment": True, "tolerant": True}
    try:
        return esprima.parseScript(code, opts), code, shebang
    except Exception as script_err:
        try:
            return esprima.parseModule(code, opts), code, shebang
        except Exception as module_err:
            raise RuntimeError(f"script mode: {script_err} | module mode: {module_err}")


def is_node(x) -> bool:
    return isinstance(getattr(x, "type", None), str) and getattr(x, "range", None) is not None


def children(node):
    for key, val in vars(node).items():
        if key in SKIP_KEYS:
            continue
        if isinstance(val, list):
            for v in val:
                if is_node(v):
                    yield v
        elif is_node(val):
            yield val


def key_name(key_node, code, computed=False):
    if key_node is None:
        return None
    if key_node.type == "Identifier" and not computed:
        return key_node.name
    if key_node.type == "Literal":
        return str(key_node.value)
    return code[key_node.range[0]:key_node.range[1]][:60]


def pattern_names(p):
    """Names bound by an Identifier / destructuring pattern."""
    if p is None:
        return []
    t = p.type
    if t == "Identifier":
        return [p.name]
    if t == "ObjectPattern":
        out = []
        for prop in p.properties:
            out += pattern_names(getattr(prop, "value", None) or getattr(prop, "argument", None))
        return out
    if t == "ArrayPattern":
        return [n for e in p.elements for n in pattern_names(e)]
    if t == "AssignmentPattern":
        return pattern_names(p.left)
    if t == "RestElement":
        return pattern_names(p.argument)
    return []


def resolve_function(node, parent, grand, cls, code):
    """
    Returns (name, kind, unit_text).
    unit_text is the source that makes the function meaningful on its own:
    e.g. for `const f = () => 1` we keep the whole declaration, for a class
    method we keep the full `name(args) {...}` definition.
    """
    own = code[node.range[0]:node.range[1]]
    name, text = None, own
    ptype = parent.type if parent is not None else None

    if node.type == "FunctionDeclaration":
        name = node.id.name if node.id else None
    elif getattr(node, "id", None) is not None:
        name = node.id.name

    if ptype == "MethodDefinition" and parent.value is node:
        mname = key_name(parent.key, code, parent.computed)
        name = name or mname
        if cls and mname:
            name = f"{cls}.{mname}"
        text = code[parent.range[0]:parent.range[1]]
    elif ptype == "Property" and parent.value is node:
        name = name or key_name(parent.key, code, parent.computed)
        text = code[parent.range[0]:parent.range[1]]
    elif ptype == "VariableDeclarator" and parent.init is node:
        if parent.id.type == "Identifier":
            name = name or parent.id.name
        kind = grand.kind if grand is not None and grand.type == "VariableDeclaration" else "var"
        text = f"{kind} {code[parent.range[0]:parent.range[1]]};"
    elif ptype == "AssignmentExpression" and parent.right is node:
        left = code[parent.left.range[0]:parent.left.range[1]]
        name = name or left[:60]
        text = code[parent.range[0]:parent.range[1]] + ";"
    elif ptype == "AssignmentPattern" and parent.right is node:
        name = name or "default_param"

    kind_label = {
        "FunctionDeclaration": "declaration",
        "FunctionExpression": "expression",
        "ArrowFunctionExpression": "arrow",
    }[node.type]
    if getattr(node, "async", False) or getattr(node, "isAsync", False):
        kind_label = "async " + kind_label
    if getattr(node, "generator", False):
        kind_label += " generator"
    return (name or "anonymous"), kind_label, text


def safe_filename(name: str, limit: int = 80) -> str:
    s = re.sub(r"[^A-Za-z0-9_.\-]", "_", name).strip("._") or "anonymous"
    return s[:limit]


# --------------------------------------------------------------------------
# Core analysis of one parsed chunk
# --------------------------------------------------------------------------
def analyse_chunk(tree, code, line_offset, chunk_no, top_level_only, page: PageResult,
                  shebang=False):
    # Comments
    for c in getattr(tree, "comments", None) or []:
        raw = code[c.range[0]:c.range[1]]
        if not raw.startswith(("//", "/*")):          # parser may strip markers
            raw = f"//{c.value}" if c.type == "Line" else f"/*{c.value}*/"
        if shebang and c.range[0] == 0:
            raw = "#!" + raw[2:]
        page.comments.append((c.loc.start.line + line_offset, c.type, raw))

    # Iterative DFS: (node, parent, grandparent, scope_name, class_name, func_depth)
    stack = [(tree, None, None, "<global>", None, 0)]
    while stack:
        node, parent, grand, scope, cls, depth = stack.pop()
        child_scope, child_cls, child_depth = scope, cls, depth

        if node.type in FUNC_TYPES:
            name, kind, text = resolve_function(node, parent, grand, cls, code)
            if not (top_level_only and depth > 0):
                page.functions.append(FuncRecord(
                    name=name, kind=kind, text=text,
                    start=node.range[0], chunk=chunk_no,
                    start_line=node.loc.start.line + line_offset,
                    end_line=node.loc.end.line + line_offset))
            child_scope, child_depth = name, depth + 1

        elif node.type in CLASS_TYPES:
            child_cls = node.id.name if getattr(node, "id", None) else "anonymous_class"

        elif node.type == "VariableDeclaration":
            for d in node.declarations:
                init = ""
                if d.init is not None:
                    init = code[d.init.range[0]:d.init.range[1]]
                    init = " ".join(init.split())
                    if len(init) > 70:
                        init = init[:67] + "..."
                for n in pattern_names(d.id):
                    page.variables.append({
                        "kind": node.kind, "name": n, "scope": scope,
                        "line": d.loc.start.line + line_offset, "init": init})

        for ch in children(node):
            stack.append((ch, node, parent, child_scope, child_cls, child_depth))


def process_file(page_no: int, path: Path, top_level_only: bool) -> PageResult:
    is_html = path.suffix.lower() in HTML_EXT
    page = PageResult(page=page_no, source=str(path),
                      source_type="html" if is_html else "js")
    try:
        src = read_text(path)
    except Exception as e:
        page.status, page.errors = "error", [f"cannot read file: {e}"]
        return page

    chunks = list(html_script_chunks(src)) if is_html else [(src, 0)]
    if is_html and not chunks:
        page.errors.append("no inline <script> blocks found")

    parsed_ok = 0
    for i, (code, offset) in enumerate(chunks, start=1):
        try:
            tree, code, shebang = parse_js(code)
            analyse_chunk(tree, code, offset, i, top_level_only, page, shebang)
            parsed_ok += 1
        except Exception as e:
            label = f"script block {i}" if is_html else "file"
            page.errors.append(f"{label}: {str(e)[:300]}")

    if chunks and parsed_ok == 0:
        page.status = "error"
    elif page.errors and chunks:
        page.status = "partial" if parsed_ok else "error"

    # source order, then assign IDs  (page.index)
    page.functions.sort(key=lambda f: (f.chunk, f.start))
    return page


# --------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------
def write_function_files(page: PageResult, out_dir: Path, header: bool):
    for idx, fn in enumerate(page.functions, start=1):
        fn.func_id = f"{page.page}.{idx}"
        fn_name = fn.name or "anonymous"
        fn.out_file = f"{fn.func_id}_{safe_filename(fn_name)}.js"
        body = fn.text
        if header:
            body = (f"// Page {page.page} | ID {fn.func_id} | {fn.name} ({fn.kind})\n"
                    f"// Source: {page.source}  lines {fn.start_line}-{fn.end_line}\n\n{body}")
        (out_dir / fn.out_file).write_text(body + "\n", encoding="utf-8")


def write_numbering_map(pages, out_dir: Path):
    data = {"pages": []}
    for p in pages:
        data["pages"].append({
            "page": p.page,
            "source_file": p.source,
            "source_type": p.source_type,
            "status": p.status,
            "errors": p.errors,
            "functions": [{
                "id": f.func_id, "name": f.name, "kind": f.kind,
                "lines": [f.start_line, f.end_line],
                "output_file": str(out_dir / f.out_file),
            } for f in p.functions],
        })
    (out_dir / "numbering_map.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_comments(pages, out_dir: Path):
    lines = []
    for p in pages:
        lines.append(f"===== Page {p.page} | {p.source} =====")
        if p.status == "error":
            lines.append("  (file could not be parsed - no comments extracted)")
        for line, kind, text in sorted(p.comments):
            first, *rest = text.splitlines() or [""]
            lines.append(f"[Page {p.page} | L{line} | {kind}] {first}")
            lines += [f"    {r}" for r in rest]
        lines.append("")
    (out_dir / "comments.txt").write_text("\n".join(lines), encoding="utf-8")


def write_variables(pages, out_dir: Path):
    lines = []
    for p in pages:
        lines.append(f"===== Page {p.page} | {p.source} =====")
        if p.status == "error":
            lines.append("  (file could not be parsed - no variables extracted)")
        for v in sorted(p.variables, key=lambda v: v["line"]):
            init = f" = {v['init']}" if v["init"] else ""
            lines.append(f"[Page {p.page} | L{v['line']}] {v['kind']} {v['name']}{init}"
                         f"   (scope: {v['scope']})")
        lines.append("")
    (out_dir / "variables.txt").write_text("\n".join(lines), encoding="utf-8")


def build_semantic_chunks(page: PageResult, source_code: str, max_lines: int = 200):
    """Create AI-friendly chunks from a single page.

    We keep the full source as the primary context and emit a small number of
    key slices instead of every anonymous function. This keeps the bundle
    meaningful for LLM analysis while staying within a practical token limit.
    """
    source_code = normalize_minified_js(source_code)
    lines = source_code.splitlines()
    if not lines:
        return []

    interesting = [
        r"document|window|Salla|script|fetch|XMLHttpRequest|appendChild|addEventListener|currentScript|onReady|setTimeout|location|URL|MutationObserver"
    ]

    chunks = []
    full = "\n".join(lines).rstrip() + "\n"
    chunks.append({"name": "full", "kind": "full", "text": full, "lines": list(range(1, len(lines) + 1))})

    if len(lines) <= max_lines:
        return chunks

    head = lines[:max_lines]
    tail = lines[-max_lines:]
    chunks.append({"name": "head", "kind": "head", "text": "\n".join(head) + "\n", "lines": list(range(1, len(head) + 1))})
    chunks.append({"name": "tail", "kind": "tail", "text": "\n".join(tail) + "\n", "lines": list(range(len(lines) - len(tail) + 1, len(lines) + 1))})

    hits = []
    for idx, line in enumerate(lines, start=1):
        if re.search(interesting[0], line, flags=re.IGNORECASE):
            hits.append(idx)

    if hits:
        chunk_lines = []
        for line_no in hits:
            start = max(1, line_no - 18)
            end = min(len(lines), line_no + 22)
            chunk_lines.append((start, end))

        merged = []
        for start, end in sorted(chunk_lines):
            if not merged or start > merged[-1][1] + 5:
                merged.append([start, end])
            else:
                merged[-1][1] = max(merged[-1][1], end)

        for idx, (start, end) in enumerate(merged[:4], start=1):
            chunk = lines[start - 1:end]
            if chunk:
                chunks.append({
                    "name": f"critical_{idx}",
                    "kind": "critical",
                    "text": "\n".join(chunk) + "\n",
                    "lines": list(range(start, end + 1)),
                })

    unique = []
    seen = set()
    for chunk in chunks:
        key = (chunk["name"], chunk["kind"], tuple(chunk["lines"]))
        if key not in seen:
            unique.append(chunk)
            seen.add(key)
    return unique


def write_semantic_chunks(pages, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {"pages": []}

    for page in pages:
        source_path = Path(page.source)
        if not source_path.exists():
            continue
        src = read_text(source_path)
        chunks = build_semantic_chunks(page, src)
        page_summary = {
            "page": page.page,
            "source_file": page.source,
            "chunks": [],
        }

        for idx, chunk in enumerate(chunks, start=1):
            file_name = f"{page.page}.{idx}_{chunk['name']}.js"
            out_path = out_dir / file_name
            out_path.write_text(chunk["text"], encoding="utf-8")
            page_summary["chunks"].append({
                "index": idx,
                "name": chunk["name"],
                "kind": chunk["kind"],
                "lines": chunk["lines"],
                "output_file": str(out_path),
            })

        summary["pages"].append(page_summary)

    (out_dir / "semantic_chunks_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Extract every function, comment and variable from JS/HTML files.")
    ap.add_argument("input_dir", help="directory containing .js/.mjs/.cjs/.html/.htm files")
    ap.add_argument("-o", "--output", default="./extracted_output", help="output directory")
    ap.add_argument("-r", "--recursive", action="store_true", help="scan sub-directories too")
    ap.add_argument("--top-level-only", action="store_true",
                    help="skip functions nested inside other functions")
    ap.add_argument("--header", action="store_true",
                    help="prepend a traceability comment to each function file")
    ap.add_argument("--semantic-only", action="store_true",
                    help="generate only semantic chunks and skip function-based extraction output")
    args = ap.parse_args(argv)

    in_dir, out_dir = Path(args.input_dir), Path(args.output)
    if not in_dir.is_dir():
        print(f"error: '{in_dir}' is not a directory", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(message)s",
        handlers=[logging.StreamHandler(),
                  logging.FileHandler(out_dir / "errors.log", mode="w", encoding="utf-8")])

    files = collect_files(in_dir, args.recursive)
    if not files:
        log.error("no .js/.mjs/.cjs/.html/.htm files found in %s", in_dir)
        return 1

    pages = []
    for page_no, path in enumerate(files, start=1):
        page = process_file(page_no, path, args.top_level_only)
        if not args.semantic_only:
            write_function_files(page, out_dir, args.header)
        pages.append(page)
        msg = f"Page {page_no}: {path.name} -> {len(page.functions)} functions [{page.status}]"
        if page.status == "ok":
            log.info(msg)
        else:
            log.warning(msg)
            for e in page.errors:
                log.warning("    %s", e)

    if args.semantic_only:
        write_semantic_chunks(pages, out_dir)
        return 0

    write_numbering_map(pages, out_dir)
    write_comments(pages, out_dir)
    write_variables(pages, out_dir)
    write_semantic_chunks(pages, out_dir)

    total = sum(len(p.functions) for p in pages)
    bad = sum(1 for p in pages if p.status != "ok")
    log.info("Done: %d pages, %d functions, %d pages with problems. Output: %s",
             len(pages), total, bad, out_dir.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
