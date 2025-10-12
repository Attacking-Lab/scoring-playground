"""
Convert gameserver data into a format scoring-playground can understand.
"""

import argparse
import json
import csv
from types import SimpleNamespace
from collections import defaultdict

parser = argparse.ArgumentParser()
parser.add_argument("-o", "--output", required=True)
args = parser.parse_args()

flag_rounds_valid = 5


def readrows(path: str):
    with open(path) as file:
        reader = csv.reader(file)
        header = next(reader)
        rows = sorted(reader, key=lambda row: int(row[0]))
        for row_list in rows:
            row_dict = dict(zip(header, row_list))
            for key, value in row_dict.items():
                if value.isdigit():
                    row_dict[key] = int(value)  # type: ignore
            yield SimpleNamespace(**row_dict)

states = {
    "SUCCESS": "OK",
    "RECOVERING": "RECOVERING",
    "MUMBLE": "MUMBLE",
    "OFFLINE": "OFFLINE",
    "TIMEOUT": "ERROR",
    "INTERNAL_ERROR": "ERROR",
    "CRASHED": "ERROR",
}

data = {}

flagstorecnt = 0
flagstoremap = {}
services = {}
service_names = {}
for row in readrows("upstream/services.csv"):
    services[row.name] = {
        "flagstores": tuple(flagstorecnt + i for i in range(row.num_payloads)),
    }
    for i in range(row.num_payloads):
        flagstoremap[row.id, i] = flagstorecnt + i
    flagstorecnt += row.num_payloads
    service_names[row.id] = row.name
data["services"] = services

teams = []
team_names = {}
for row in readrows("upstream/teams.csv"):
    teams.append(row.name)
    team_names[row.id] = row.name
data["teams"] = teams

from collections import defaultdict

rounds = defaultdict(
    lambda: defaultdict(
        lambda: {
            "service_states": {},
            "flags_stored": defaultdict(lambda: {}),
            "flags_captured": [],
        }
    )
)
flagmap = {}
flagstates = defaultdict(lambda: {})
flagcnt = 0
for row in readrows("upstream/checker_results.csv"):
    team_name = team_names[row.team_id]
    service_name = service_names[row.service_id]
    for flagstore_id in services[service_names[row.service_id]]["flagstores"]:
        rounds[row.tick][team_name]["flags_stored"][service_name][flagstore_id] = (
            flagcnt
        )
        flagmap[(row.tick, row.team_id, row.service_id, flagstore_id)] = flagcnt
        flagcnt += 1

    not_ok_ticks = set()
    for key, flag_status in json.loads(row.data).items():
        related_tick, flagstore_id_ = key.split("_", 1)
        related_tick, flagstore_id_ = int(related_tick), int(flagstore_id_)
        flag_status = "OK" if flag_status == "OK" else "MISSING"
        if flag_status != "OK" and related_tick >= row.tick - flag_rounds_valid:
            not_ok_ticks.add(related_tick)
        if related_tick <= row.tick - flag_rounds_valid:
            continue
        flagstore_id = flagstoremap[row.service_id, flagstore_id_]
        flag_key = (related_tick, row.team_id, row.service_id, flagstore_id)
        if (flagid := flagmap.get(flag_key)) is not None:
            flagstates[row.tick][flagid] = flag_status
        else:
            assert flag_status != "OK"

    status = states[row.status]
    if status == "RECOVERING" and not_ok_ticks == {row.tick - flag_rounds_valid}:
        status = "OK" # from hotfix for validity period
    rounds[row.tick][team_name]["service_states"][service_name] = status

for row in readrows("upstream/submitted_flags.csv"):
    flagstore_id = flagstoremap[row.service_id, row.payload]
    flag_key = (row.tick_issued, row.team_id, row.service_id, flagstore_id)
    flagid = flagmap[flag_key]
    team_name = team_names[row.submitted_by]
    if row.tick_issued <= row.tick_submitted - flag_rounds_valid:
        continue
    rounds[row.tick_submitted][team_name]["flags_captured"].append(flagid)

roundlist = []
for _, row in sorted(rounds.items()):
    roundlist.append(row)
data["rounds"] = roundlist

flagstatelist = []
for _, states in sorted(flagstates.items()):
    flagstatelist.append(states)
data["flag_states"] = flagstatelist

data["config"] = {
    "flag_validity": flag_rounds_valid,
}

with open(args.output, "w") as file:
    json.dump(data, file)
