import collections
import pathlib
import json

ctf = {
    "services": {},
    "teams": [],
    "rounds": [],
    "config": {
        "flag_validity": 5,
        "flag_retention": 5,
    },
}

codemap = {
    "101": "OK",
    "104": "DOWN",
    "110": "ERROR",
}

data_dir = pathlib.Path("upstream/data")
output_data = pathlib.Path("data.json")
output_scores = pathlib.Path("scores.json")

flagstore_ids = {}  # servicename: id
team_map = {}  # id: name
svc_map = {}  # id: name

with (data_dir / "services.csv").open() as file:
    rows = list(file.read().strip().split("\n"))
    for row in rows[1:]:
        id, name, shortname = row.split(",")
        fsid = len(flagstore_ids)
        flagstore_ids[name] = fsid
        svc_map[id] = name
        ctf["services"][name] = {
            "flagstores": [fsid],
        }

with (data_dir / "teams.csv").open() as file:
    rows = list(file.read().strip().split("\n"))
    for row in rows[1:]:
        id, name, shortname = row.split(",")
        ctf["teams"].append(name)
        team_map[id] = name


def create_trd(team, round_id):
    while round_id >= len(ctf["rounds"]):
        ctf["rounds"].append({})
    if team not in ctf["rounds"][round_id]:
        ctf["rounds"][round_id][team] = {
            "service_states": {},
            "flags_stored": {ss: {} for ss in svc_map.values()},
            "flags_captured": [],
        }


with (data_dir / "flags.csv").open() as file:
    rows = list(file.read().strip().split("\n"))
    for row in rows[1:]:
        id, flag, round, status, teamId, serviceId = row.split(",")
        team = team_map[teamId]
        create_trd(team, int(round) - 1)
        assert status in ("READY", "FAILED"), row
        if status == "READY":
            ctf["rounds"][int(round) - 1][team]["flags_stored"][svc_map[serviceId]][
                flagstore_ids[svc_map[serviceId]]
            ] = int(id)

checks = collections.defaultdict(dict)
max_round = 0
with (data_dir / "scoreboard_checks.csv").open() as file:
    rows = list(file.read().strip().split("\n"))
    for row in rows[1:]:
        round, teamId, serviceShortname, action, exitCode, stdout = row.split(",")
        create_trd(team_map[teamId], int(round) - 1)
        assert action in ("CHECK_SLA", "GET_FLAG", "PUT_FLAG"), row
        assert (exitCode == "101") == (stdout == "OK"), row
        checks[(int(round) - 1, team_map[teamId], serviceShortname)][action] = codemap[exitCode]
        max_round = max(max_round, int(round) - 1)

for rr in range(max_round + 1):
    for tt in ctf["teams"]:
        create_trd(tt, rr)
        for ss in ctf["services"]:
            if rr == max_round:
                put = "OK"
            else:
                put = checks[(rr, tt, ss)]["PUT_FLAG"]
            sla = checks[(rr, tt, ss)]["CHECK_SLA"]
            # getflag is not called if previous 5 PUT_FLAG failed, per rules
            get = checks[(rr, tt, ss)].get("GET_FLAG")
            if all(v in ("ERROR", None) for v in (put, sla, get)):
                state = "ERROR"
            elif all(v in ("OK", "ERROR", None) for v in (put, sla, get)):
                state = "OK"
            elif put == "OK" and sla == "OK" and get == "DOWN":
                state = "RECOVERING"
            else:
                state = "MUMBLE"
            ctf["rounds"][rr][tt]["service_states"][ss] = state

with (data_dir / "stolen_flags.csv").open() as file:
    rows = list(file.read().strip().split("\n"))
    for row in rows[1:]:
        id, attackerId, flagId, round, timestamp = row.split(",")
        ctf["rounds"][int(round) - 1][team_map[attackerId]]["flags_captured"].append(
            int(flagId)
        )

scores = collections.defaultdict(lambda: {})
import csv
with (data_dir / "scoreboard_teams.csv").open() as file:
    rows = list(file.read().strip().split("\n"))
    rows = csv.reader(rows)
    next(rows) # skip header
    for row in rows:
        round, id, adscore, _, _, info, _ = row
        scores[int(round)][team_map[id]] = {"combined": float(adscore), "meta": json.loads(info)}
assert set(range(len(scores))) == set(scores)
scores = [v for _,v in sorted(scores.items())]

with output_data.open("w") as out:
    json.dump(ctf, out)

with output_scores.open("w") as out:
    json.dump(scores, out)
