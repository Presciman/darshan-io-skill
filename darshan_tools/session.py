"""One Darshan log, ready for an agent: its filled two-layer schema, its exact facts, and the tools.

    s = Session("job.darshan")                 # nodes=N only if DXT did not trace every rank
    s.call("darshan", {"view": "cards"})       # any tool: outline search get darshan calc
"""
import json
import os

from . import toolbox
from .evidence import SchemaEvidence, run_tool
from .schema import darshan_to_schema as d2s


def fill_schema(log, records=False, env_file=None):
    """The filled two-layer schema for one log. `env_file` is the job's saved batch environment
    (KEY=VALUE lines), if you have one; without it, node count and host list come from DXT."""
    env = d2s.load_env_file(env_file)
    doc = d2s.process(log, env, {})
    if not records:
        d2s._strip_records(doc)
    return json.loads(json.dumps(doc, default=str))


class Session:
    def __init__(self, log, nodes=None, env_file=None):
        self.log = os.path.abspath(log)
        if not os.path.isfile(self.log):
            raise FileNotFoundError(self.log)
        self.nodes = int(nodes) if nodes else None
        from . import facts as _facts           # PyDarshan, numpy, pandas: only when a log is opened
        # Facts first: opening a log through the schema converter first changes what PyDarshan
        # reports for that file afterwards in the same process (an APMPI record count drops by one).
        f = _facts.extract(self.log)
        self.doc = fill_schema(self.log, env_file=env_file)
        f["nodes"] = self.nodes
        self.facts = f
        self.tb = toolbox.Toolbox(f)
        self.evidence = SchemaEvidence(self.log, doc=self.doc)
        self.evidence.tb = self.tb

    def call(self, name, args=None):
        """Run one tool (outline, search, get, darshan, calc). Returns (text, ok)."""
        return run_tool(self.evidence, name, args or {})

    def summary(self):
        j = self.facts["job"]
        return dict(log=self.log, nprocs=j.get("nprocs"), run_time_s=j.get("run_time"),
                    modules=self.facts.get("modules"), nodes=toolbox._nodes(self.facts)[0],
                    schema_version=(self.doc.get("meta") or {}).get("schema_version"))
