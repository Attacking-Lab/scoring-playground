import argparse
from collections import defaultdict
import json

import psycopg2

parser = argparse.ArgumentParser()
parser.add_argument("-o", "--output", required=True)
args = parser.parse_args()

connection = psycopg2.connect(
    host="localhost",
    database="postgres",
    user="postgres",
    password="postgres",
)

cursor = connection.cursor()

service_status = {
    0: "OK",
    1: "OFFLINE", # Error in the network connection, e.g. a timeout or connection abort
    2: "MUMBLE", # Service is available, but not behaving as expected
    3: "MUMBLE", # Flag missing
    4: "RECOVERING",
    5: "ERROR"
}
service_status_missing = "ERROR"

cursor.execute("SELECT valid_ticks from scoring_gamecontrol")
valid_ticks = (cursor.fetchone() or [])[0]

service_names = {}
cursor.execute("SELECT id,name FROM scoring_service")
for service_id,name in cursor.fetchall():
    service_names[service_id] = name

team_names = {}
cursor.execute("SELECT id,username FROM auth_user")
for team_id,name in cursor.fetchall():
    team_names[team_id] = name

round_status = defaultdict(lambda: defaultdict(lambda: {}))
cursor.execute("SELECT tick,status,service_id,team_id FROM scoring_statuscheck")
for tick,status,service_id,team_id in cursor.fetchall():
    assert team_id != 1
    round_status[tick][team_id][service_id] = service_status[status]

flags_stored = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: 0))))
cursor.execute("SELECT id,tick,protecting_team_id,service_id FROM scoring_flag")
for flag_id,tick,victim_id,service_id in cursor.fetchall():
    assert victim_id != 1
    flags_stored[tick][victim_id][service_id][str(service_id)] = flag_id

flags_captured = defaultdict(lambda: defaultdict(lambda: []))
cursor.execute("SELECT tick,capturing_team_id,flag_id FROM scoring_capture")
for tick,attacker_id,flag_id in cursor.fetchall():
    assert attacker_id != 1
    flags_captured[tick][attacker_id].append(flag_id)

cursor.execute("SELECT current_tick FROM scoring_gamecontrol")
max_tick = (cursor.fetchone() or [])[0]
assert max_tick in round_status
assert 0 in round_status

rounds = []
for round_id in range(0, max_tick):
    round_info = {}
    for team_id,team_name in team_names.items():
        team_info = {
            "service_states": {},
            "flags_stored": {},
            "flags_captured": flags_captured[round_id][team_id]
        }
        for service_id,service_name in service_names.items():
            team_info["service_states"][service_name] = round_status[round_id][team_id].get(service_id, "OFFLINE")
            team_info["flags_stored"][service_name] = flags_stored[round_id][team_id][service_id]
        round_info[team_name] = team_info
    rounds.append(round_info)

services = {}
for service_id, service_name in service_names.items():
    services[service_name] = {"flagstores": [service_id]}
teams = [name for _,name in sorted(team_names.items())]
ctf = {
    "services": services,
    "teams": teams,
    "rounds": rounds,
    "config": {
        "flag_validity": valid_ticks
    }
}

with open(args.output, "w") as file:
    json.dump(ctf, file, indent=4)
