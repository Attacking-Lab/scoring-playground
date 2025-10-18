import json
from collections import defaultdict
from typing import Any

import psycopg2

connection = psycopg2.connect(
    host="localhost",
    database="postgres",
    user="postgres",
    password="postgres",
)

last_round_id = 211

cursor = connection.cursor()

teams = []
team_names = {}
cursor.execute("SELECT id,name FROM teams ORDER by id")
for team_id, team_name in cursor.fetchall():
    teams.append(team_name)
    team_names[team_id] = team_name

services = {}
flagstore_lut = {}
flagstore_count = 0
cursor.execute("SELECT id,name,num_payloads,flags_per_round FROM services ORDER BY id")
service_names = {}
for svc_id, svc_name, flag_variants, flags_per_round in cursor.fetchall():
    service_names[svc_id] = svc_name
    services[svc_name] = {"flagstores": []}
    for flagstore_index in range(flag_variants):
        services[svc_name]["flagstores"].append(flagstore_count)
        flagstore_lut[svc_id, flagstore_index] = flagstore_count
        flagstore_count += 1
sns = list(services.keys())

checker_results = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: None)))
cursor.execute("SELECT round,team_id,service_id,status FROM checker_results")
for round_id, team_id, service_id, checker_result in cursor.fetchall():
    checker_results[round_id][team_names[team_id]][service_names[service_id]] = checker_result

captured: Any = defaultdict(
    lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: set())))
)
cursor.execute(
    "SELECT round_submitted,round_issued,submitted_by,"
    "team_id,service_id,payload FROM submitted_flags"
)
for row in cursor.fetchall():
    round_id, issued_round_id, attacker_id = row[:3]
    victim_id, service_id, flagstore_id_ = row[3:]
    capture_info = (issued_round_id, team_names[victim_id])
    flagstore_id = flagstore_lut[service_id, flagstore_id_]
    captured[round_id][team_names[attacker_id]][service_names[service_id]][flagstore_id].add(capture_info)

rounds = []
next_flag_id = 0
flag_cache = {}
def get_flag(rnd: int, victim: str, svc: str, fs: int):
    global next_flag_id
    key = (rnd, victim, svc, fs)
    if key not in flag_cache:
        flag_cache[key] = next_flag_id
        next_flag_id += 1
    return flag_cache[key]
pending_flags = set()
cursor.execute("SELECT DISTINCT round FROM checker_results ORDER BY round")
rounds_ = [r for (r,) in cursor.fetchall() if r > 0]
rounds = []
for round_index, round_id in enumerate(rounds_):
    assert round_index + 1 == round_id
    if round_id > last_round_id:
        break
    rnd = {}

    cursor.execute(
        f"select count(distinct team_id) from checker_results where round = {round_id}"
    )
    (online_teams,) = cursor.fetchone()  # type: ignore

    for team in teams:
        service_states = {}
        flags_stored = {}
        for service in services:
            team_results = checker_results[round_id][team]
            vpn_state_ = any(result is not None for result in (team_results or {}).values())
            vpn_state = "online" if vpn_state_ else "offline"
            result = team_results[service]
            match result:
                case None: result = 'OFFLINE'
                case 'SUCCESS': result = 'OK'
                case 'REVOKED': result = 'ERROR'; revoked = True # XXX handle that
                case 'CRASHED': result = 'ERROR'
                case 'FLAGMISSING': result = 'RECOVERING'
                case 'MUMBLE' | 'OFFLINE': pass
                case 'TIMEOUT': result = 'MUMBLE' # XXX?
                case _: raise KeyError(result)
            service_states[service] = result
            if vpn_state == 'offline':
                assert result == 'OFFLINE'
            flags_stored[service] = {}
            for flagstore_id in services[service]["flagstores"]:
                if result in ('ERROR', 'OFFLINE'):
                    # only stored successfully if proven to be stored
                    pending_flags.add((round_id, team, service, flagstore_id))
                else:
                    flags_stored[service][flagstore_id] = get_flag(round_id, team, service, flagstore_id)
        rnd[team] = {
            'service_states': service_states,
            'flags_stored': flags_stored,
            'flags_captured': [],
        }
    rounds.append(rnd)
    for team in teams:
        for service, service_data in services.items():
            for flagstore_id in service_data["flagstores"]:
                for src_round, victim in captured[round_id][team][service][flagstore_id]:
                    flag_id = get_flag(src_round, victim, service, flagstore_id)
                    if (src_round, victim, service, flagstore_id) in pending_flags:
                        rounds[src_round-1][victim]['flags_stored'][service][flagstore_id] = flag_id
                    rounds[-1][team]['flags_captured'].append(flag_id)


ctf = {
    'services': services,
    'teams': teams,
    'rounds': rounds,
    'config': {
        'flag_retention': 10,
        'flag_validity': 10,
        'messages': [
            'This dataset lacks information on which flags were stored successfully. Flags from OFFLINE or ERROR ticks are only considered stored if we see evidence of them being captured.'
        ]
    }
}
with open("data.json", 'w') as writer:
    json.dump(ctf, writer, indent=4)

cursor.execute(
    "SELECT round,team_id,service_id,sla_points,off_points,def_points FROM team_points"
)
team_points = defaultdict(lambda: defaultdict(lambda: {"sla": 0, "defense": 0, "attack": 0}))
for round_id, team_id, service_id, slapts, atkpts, defpts in cursor.fetchall():
    team_points[round_id][team_id]["sla"] += slapts
    team_points[round_id][team_id]["defense"] += defpts
    team_points[round_id][team_id]["attack"] += atkpts

cursor.execute(f"SELECT round, team_id,points FROM team_rankings")
scores = defaultdict(lambda: {})
for round_id, team_id, total in cursor.fetchall():
    if round_id > last_round_id: break
    scores[round_id][team_names[team_id]] = {"combined": total, "categories": team_points[round_id][team_id]}

assert 0 not in scores
scores[0] = {team: {"combined": 0} for team in teams}
assert set(range(len(scores))) == set(scores)
scores = [v for _,v in sorted(scores.items())]
with open("scores.json", "w") as file:
    json.dump(scores, file, indent=4)
