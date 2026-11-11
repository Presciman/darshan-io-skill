"""The Darshan tools as an MCP server (stdio; no dependencies beyond PyDarshan).

    darshan-tools-mcp            (or: python -m darshan_tools.mcp_server)

Tools: open_log, then outline / search / get over the filled two-layer schema, darshan (exact
facts and cards) and calc (exact arithmetic). Each takes an optional `log`; without it they act on
the log opened last. The server's instructions explain the schema and how to answer from the cards.
"""
import copy
import json
import os
import sys
import traceback

from . import toolbox
from .evidence import SCHEMA_NOTE, TOOLS as SCHEMA_TOOLS
from .session import Session

PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")

INSTRUCTIONS = (
    "Darshan I/O tools. Call open_log(log) on a .darshan file first (it fills the two-layer schema "
    "and extracts the exact facts; a few seconds), then follow the rules below. Pair them with the "
    "darshan-analysis skill as your methodology.\n\n" + SCHEMA_NOTE + "\n\n" + toolbox.PRECISION_NOTE)

LOG_PROP = {"log": {"type": "string",
                    "description": "path of an opened .darshan log (default: the one opened last)"}}


def _with_log(tool):
    t = copy.deepcopy(tool["function"])
    params = t.setdefault("parameters", {"type": "object", "properties": {}})
    params.setdefault("properties", {}).update(LOG_PROP)
    return {"name": t["name"], "description": t["description"], "inputSchema": params}


TOOLS = [{
    "name": "open_log",
    "description": "Open a .darshan log: fill its two-layer schema and extract its exact facts. "
                   "Call this before any other tool. `nodes` is the node count, needed only when "
                   "DXT did not trace every rank.",
    "inputSchema": {"type": "object", "properties": {
        "log": {"type": "string", "description": "path to the .darshan file"},
        "nodes": {"type": "integer"}},
        "required": ["log"]}}] + [_with_log(t) for t in SCHEMA_TOOLS + toolbox.TOOLS]


class Server:
    def __init__(self):
        self.sessions, self.current = {}, None

    def _session(self, args):
        log = (args or {}).get("log")
        key = os.path.abspath(log) if log else self.current
        if key is None:
            raise ValueError("no log is open: call open_log(log) first")
        if key not in self.sessions:
            raise ValueError("%s is not open: call open_log first" % log)
        return self.sessions[key]

    def call(self, name, args):
        args = dict(args or {})
        if name == "open_log":
            key = os.path.abspath(args["log"])
            nodes = int(args["nodes"]) if args.get("nodes") else None
            s = self.sessions.get(key)
            # A log is read once per server: PyDarshan reads a file differently the second time
            # in one process.
            if s is None:
                s = Session(args["log"], nodes=nodes)
            elif nodes != s.nodes:
                s.nodes = s.facts["nodes"] = nodes
            self.sessions[s.log], self.current = s, s.log
            return json.dumps(s.summary(), indent=1) + "\nNext: darshan(view='cards').", False
        s = self._session(args)
        args.pop("log", None)
        text, ok = s.call(name, args)
        return text, not ok

    # ---------------------------------------------------------------- JSON-RPC over stdio
    def handle(self, msg):
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:                                   # a notification: never answered
            return None
        try:
            if method == "initialize":
                want = (msg.get("params") or {}).get("protocolVersion")
                return self._ok(mid, {
                    "protocolVersion": want if want in PROTOCOLS else PROTOCOLS[0],
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "darshan-tools", "version": "1.0.0"},
                    "instructions": INSTRUCTIONS})
            if method == "ping":
                return self._ok(mid, {})
            if method == "tools/list":
                return self._ok(mid, {"tools": TOOLS})
            if method == "tools/call":
                p = msg.get("params") or {}
                try:
                    text, is_error = self.call(p.get("name"), p.get("arguments"))
                except Exception as exc:                  # noqa: BLE001
                    text, is_error = "error: %s: %s" % (type(exc).__name__, exc), True
                return self._ok(mid, {"content": [{"type": "text", "text": text}], "isError": is_error})
            if method in ("resources/list", "prompts/list"):
                return self._ok(mid, {method.split("/")[0]: []})
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "unknown method %s" % method}}
        except Exception as exc:                          # noqa: BLE001
            traceback.print_exc(file=sys.stderr)
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(exc)}}

    @staticmethod
    def _ok(mid, result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def serve(self, rfile=sys.stdin, wfile=sys.stdout):
        for line in rfile:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            else:
                out = ([r for r in (self.handle(m) for m in msg) if r] if isinstance(msg, list)
                       else self.handle(msg))
            if out:
                wfile.write(json.dumps(out) + "\n")
                wfile.flush()


def main(argv=None):
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    Server().serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
