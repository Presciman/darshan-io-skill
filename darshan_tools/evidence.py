"""The schema tools (outline / search / get over the filled two-layer schema) and the dispatcher
that runs any of the agent's tools: these three plus darshan() and calc() from toolbox."""
import json
import re

SCHEMA_NOTE = """YOUR EVIDENCE — a filled instance of the two-layer Darshan
analysis schema for this job. It is NOT in this prompt. Retrieve it with the
three tools below: `outline` lists every field path, `search` matches paths and
values by regex, and `get` returns the value or subtree at one dotted path.

Layer 1 (`modules`, `storage`, `traces`) holds the raw counter families grouped
by concern. Layer 2 (`insights`) holds derived relations already computed for
you: throughput, behaviour ratios, scale-normalised metrics, efficiency.

Absence is meaningful and the three kinds are distinct:
  * a key that is NOT PRESENT inside a counter group had the value 0 -- zeros
    are omitted, so treat a missing counter as zero, not as unknown;
  * a null value means the field could not be populated (unknown);
  * an empty object, or `n_records: 0`, means that module is absent from the log."""

SEARCH_CAP = 40                      # matches returned by one search()
RESULT_CHARS = 12000                 # per tool result
OUTLINE_CHARS = 24000                # outline() must never be clipped --
                                     # a clipped map hides fields from the
                                     # agent

TOOLS = [
    {"type": "function", "function": {
        "name": "outline",
        "description": "List the structure of the evidence: every field or "
                       "counter name available, without values. Call this "
                       "first to see what exists.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "search",
        "description": "Case-insensitive regular-expression search over the "
                       "evidence. Returns matching lines (raw dump) or "
                       "matching 'path = value' entries (schema).",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string",
                        "description": "Python regular expression."}},
            "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "get",
        "description": "Return one named item exactly: a counter or header "
                       "field name (raw dump), or a dotted field path and its "
                       "subtree (schema).",
        "parameters": {"type": "object", "properties": {
            "key": {"type": "string"}}, "required": ["key"]}}},
]


class SchemaEvidence:
    """The filled two-layer schema, addressed by dotted path.

    Layer-1 fields are `{value, source}` pairs, so a flat path list doubles
    every field name. `outline` collapses a pair back to the field it
    describes; `get` on that collapsed path returns the pair, so the map and
    the accessor still agree.
    """

    kind = "schema"

    def __init__(self, path, doc=None):
        self.path = path
        self.doc = doc if doc is not None else json.load(open(path))
        self.flat = {}
        self._flatten(self.doc, "")

    def _flatten(self, node, prefix):
        if isinstance(node, dict) and node:
            for k, v in node.items():
                self._flatten(v, "%s.%s" % (prefix, k) if prefix else k)
        elif isinstance(node, list):
            self.flat[prefix] = node
        elif isinstance(node, dict):
            self.flat[prefix] = {}
        else:
            self.flat[prefix] = node

    def _paths(self):
        """Field paths, with every {value, source} pair collapsed to one."""
        out, seen = [], set()
        for p in self.flat:
            head, _, leaf = p.rpartition(".")
            if leaf in ("value", "source") and head:
                sibs = {q.rpartition(".")[2] for q in self.flat
                        if q.rpartition(".")[0] == head}
                if "value" in sibs and "source" in sibs:
                    if head not in seen:
                        seen.add(head)
                        out.append(head)
                    continue
            out.append(p)
        return out

    def outline(self):
        paths = self._paths()
        return ("FIELD PATHS (%d) -- get(<path>). A path shown without a "
                "trailing .value is a {value, source} pair; get() returns "
                "both. get() on a parent path returns its whole subtree.\n%s"
                % (len(paths), "\n".join("  " + p for p in paths)))

    def search(self, pattern):
        rx = re.compile(pattern, re.I)
        hits = ["%s = %s" % (p, json.dumps(v))
                for p, v in self.flat.items()
                if rx.search(p) or rx.search(json.dumps(v))]
        return hits[:SEARCH_CAP], len(hits)

    def get(self, key):
        key = key.strip().lstrip(".")
        if key in self.flat:
            return "%s = %s" % (key, json.dumps(self.flat[key]))
        node = self.doc
        for part in key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                node = None
                break
        if node is not None:
            return "%s = %s" % (key, json.dumps(node, indent=1))
        # Leaf-name fallback: `get("POSIX_BYTES_READ")` is the natural call for
        # an analyst who knows counters but not this tree.
        tail = key.rpartition(".")[2].lower()
        hits = [p for p in self.flat if p.rpartition(".")[2].lower() == tail]
        if not hits:
            hits = [p for p in self._paths()
                    if p.rpartition(".")[2].lower() == tail]
        if len(hits) == 1:
            return self.get(hits[0])
        if hits:
            return ("%r matches %d paths; ask for one of them:\n%s"
                    % (key, len(hits), "\n".join("  " + p for p in hits[:20])))
        return None


def run_tool(ev, name, args):
    """Execute one tool call. Returns (result_text, ok)."""
    tb = getattr(ev, "tb", None)
    if tb is not None and name in ("darshan", "calc"):
        try:
            if name == "darshan":
                return tb.darshan((args or {}).get("view", "index")), True
            return tb.calc(str((args or {}).get("expression", ""))), True
        except Exception as exc:                               # noqa: BLE001
            return "error: %s: %s" % (type(exc).__name__, exc), False
    try:
        if name == "outline":
            return ev.outline()[:OUTLINE_CHARS], True
        if name == "search":
            pattern = (args or {}).get("pattern", "")
            if not pattern:
                return "error: search needs a `pattern`.", False
            try:
                hits, total = ev.search(pattern)
            except re.error as exc:
                return "error: bad regex (%s)." % exc, False
            if not hits:
                return "no match for %r." % pattern, True
            head = "%d match(es)%s:\n" % (
                total, "" if total <= SEARCH_CAP
                else " — first %d shown" % SEARCH_CAP)
            return (head + "\n".join(hits))[:RESULT_CHARS], True
        if name == "get":
            key = (args or {}).get("key", "")
            if not key:
                return "error: get needs a `key`.", False
            hit = ev.get(key)
            if hit is None:
                return ("%r is not in this evidence. Use outline() to see what "
                        "is." % key), True
            return hit[:RESULT_CHARS], True
        return "error: no such tool %r." % name, False
    except Exception as exc:                                   # noqa: BLE001
        return "error: %s: %s" % (type(exc).__name__, exc), False
