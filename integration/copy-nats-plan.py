"""Copy host-prepared NATS decoys into the integration client's home."""

import json
from pathlib import Path
import shutil
import sys

plan_path, source_home, destination = map(Path, sys.argv[1:])
plan = json.loads(plan_path.read_text())
for bind in plan["binds"]:
    target = Path(bind["dest"])
    if not target.is_relative_to(source_home):
        continue
    output = destination / target.relative_to(source_home)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bind["source"], output)
    if output.suffix == ".json":
        context = json.loads(output.read_text())
        for key in ("nkey", "ca", "creds", "cert", "key"):
            value = context.get(key)
            if isinstance(value, str) and value.startswith(str(source_home) + "/"):
                context[key] = "/tmp/.config/nats/" + str(Path(value).relative_to(source_home))
        output.write_text(json.dumps(context))
