import dataclasses
import collections

from msgspec import UNSET

from ..model import (
    CTF,
    Score,
    Scoreboard,
    ScoringFormula,
    ServiceName,
    ServiceState,
    TeamName,
)


@dataclasses.dataclass(kw_only=True)
class ATKLABv1(ScoringFormula):
    scaling_factor: float = 5.0
    nop_team: TeamName | None = TeamName("NOP")

    def evaluate(self, ctf: CTF) -> Scoreboard:
        if self.nop_team is not None and self.nop_team not in ctf.teams:
            raise KeyError(
                f"Configured NOP team {str(self.nop_team)!r} not found in the CTF data"
            )

        if ctf.config.flag_retention is UNSET:
            raise KeyError(f"No flag retention period defined in CTF data")

        scoreboard: Scoreboard = collections.defaultdict(Score.default)
        for round_id, round_data in ctf.enumerate():
            for team, team_data in round_data.items():
                score = Score.default()

                # SLA points
                for service, state in team_data.service_states.items():
                    max_flags = min(round_id + 1, ctf.config.flag_retention)
                    if state == ServiceState.OK:
                        present = max_flags
                    elif state == ServiceState.RECOVERING:
                        present = 1
                        # XXX: We assume here that flags which were present in
                        #      previous rounds are still present and returned.
                        for previous_round in reversed(
                            range(
                                max(0, round_id - ctf.config.flag_retention),
                                round_id - 1,
                            )
                        ):
                            if (
                                ctf.rounds[previous_round][team].service_states[service]
                                != ServiceState.RECOVERING
                            ):
                                break
                            present += 1
                        present = min(present, max_flags)
                    else:
                        present = 0
                    if state in (ServiceState.OK, ServiceState.RECOVERING):
                        score += Score.default(sla=present / max_flags)

                # Attack points
                for flag_id in team_data.flags_captured:
                    flag = ctf.flags[flag_id]
                    if flag.owner == team:
                        continue
                    capture_count = ctf.flag_captures[flag_id].count
                    score += Score.default(attack=(1 + 1 / capture_count) / 2)

                # Defense points
                for flagstore_data in team_data.flags_stored.values():
                    for flag_id in flagstore_data.values():
                        if count := ctf.flag_captures[flag_id].count:
                            score -= Score.default(
                                defense=(1 + count / len(ctf.teams)) / 2
                            )

                scoreboard[team] += score

        return scoreboard
