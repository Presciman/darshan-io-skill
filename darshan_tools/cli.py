"""darshan-tools: the Darshan tools from a shell.

  darshan-tools schema LOG [-o out.json] [--records] [--env-file F]   fill the two-layer schema
  darshan-tools view LOG [cards|derived|job|ranks|...] [--nodes N]     one darshan() view
  darshan-tools calc "10963279 / MiB"                                  exact arithmetic
  darshan-tools mcp                                                    the MCP server (stdio)
"""
import argparse
import json
import sys

from . import toolbox


def cmd_schema(a):
    from .session import fill_schema
    doc = fill_schema(a.log, records=a.records, env_file=a.env_file)
    text = json.dumps(doc, indent=2, default=str)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("wrote %s" % a.output, file=sys.stderr)
    else:
        print(text)


def cmd_view(a):
    from . import facts as _facts
    f = _facts.extract(a.log)
    f["nodes"] = a.nodes
    print(toolbox.Toolbox(f).darshan(a.name))


def cmd_calc(a):
    print(toolbox.Toolbox({}).calc(a.expression))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="darshan-tools", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("schema", help="fill the two-layer schema for a log")
    p.add_argument("log")
    p.add_argument("-o", "--output")
    p.add_argument("--records", action="store_true", help="keep per-record arrays")
    p.add_argument("--env-file", help="the job's saved batch environment (KEY=VALUE lines), optional")
    p.set_defaults(fn=cmd_schema)
    p = sub.add_parser("view", help="one darshan() view of a log (default: cards)")
    p.add_argument("log")
    p.add_argument("name", nargs="?", default="cards")
    p.add_argument("--nodes", type=int, help="node count, when DXT did not trace every rank")
    p.set_defaults(fn=cmd_view)
    p = sub.add_parser("calc", help="exact arithmetic")
    p.add_argument("expression")
    p.set_defaults(fn=cmd_calc)
    sub.add_parser("mcp", help="run the MCP server (stdio)", add_help=False)

    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["mcp"]:
        from . import mcp_server
        return mcp_server.main(argv[1:])
    a = ap.parse_args(argv)
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
