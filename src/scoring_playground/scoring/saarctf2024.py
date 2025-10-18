import dataclasses
import collections
import typing

from ..model import (
    CTF,
    FlagId,
    RoundId,
    Score,
    Scoreboard,
    ScoringFormula,
    ServiceName,
    ServiceState,
    TeamName,
)


@dataclasses.dataclass(kw_only=True)
class SaarCTF2024(ScoringFormula):
    """This is the scoring formula from saarCTF 2024"""

    # NB: In the saarCTF gameserver, you can configure the validity period of the flags also.
    # We place this determination on the actual CTF data, however, since flags outside of the
    # validity period are often either not recorded, not submitted, or not even captured.

    off_factor: float = 1.0
    def_factor: float = 1.0
    sla_factor: float = 1.0
    nop_team: TeamName | None = TeamName("NOP")

    defense_bug: bool = True  # There is a bug in the gameserver's calculation of defense points, see below

    @staticmethod
    def _rank(
        scoreboard: Scoreboard, teams: typing.Sequence[TeamName]
    ) -> typing.Mapping[TeamName, int]:
        ordered = sorted(((scoreboard[team].combined, team) for team in teams), reverse=True)
        previous = None
        ranking = {}
        counter = 1
        for score, team in ordered:
            rank = counter
            if previous is not None:
                previous_rank, previous_score = previous
                if previous_score == score:
                    rank = previous_rank
            ranking[team] = rank
            previous = (rank, score)
            if score > 0:
                counter += 1
        return ranking

    def evaluate(self, ctf: CTF) -> Scoreboard:
        if self.nop_team is not None and self.nop_team not in ctf.teams:
            raise KeyError(
                f"Configured NOP team {str(self.nop_team)!r} not found in the CTF data"
            )

        scoreboard: Scoreboard = collections.defaultdict(Score.default)
        for team in ctf.teams:
            _ = scoreboard[team]

        rankings: dict[RoundId, typing.Mapping[TeamName, int]] = {}
        previous_slas: dict[
            RoundId, typing.Mapping[tuple[TeamName, ServiceName], float]
        ] = {}
        num_active_teams: dict[RoundId, int] = {}
        for round_id, round_data in ctf.enumerate():
            # Compute scoreboard rankings before this round
            rankings[round_id] = SaarCTF2024._rank(scoreboard, ctf.teams)

            # Compute SLA scores and count teams
            sla: typing.MutableMapping[tuple[TeamName, ServiceName], float] = (
                collections.defaultdict(float)
            )
            active_teams: set[TeamName] = set()
            for team, team_data in round_data.items():
                for service, state in team_data.service_states.items():
                    if state == ServiceState.OK or state == ServiceState.RECOVERING:
                        active_teams.add(team)
                    if state == ServiceState.OK:
                        sla[(team, service)] += self.sla_factor
            num_active_teams[round_id] = max(1, len(active_teams))
            for team in round_data.keys():
                for service in ctf.services:
                    sla[(team, service)] *= num_active_teams[round_id] ** 0.5
                scoreboard[team] += Score.default(
                    sla=sum(sla[(team, service)] for service in ctf.services)
                )
            previous_slas[round_id] = sla

            # Compute attack scores
            captured_flags: set[FlagId] = set()
            for team, team_data in round_data.items():
                for flag_id in team_data.flags_captured:
                    flag = ctf.flags[flag_id]
                    if flag.owner == self.nop_team:
                        # These are not even submitted in saarCTF data.
                        continue
                    if team == flag.owner:
                        continue

                    if flag.round_id > 0:
                        victim_rank = rankings[flag.round_id][flag.owner]
                    else:
                        # In the first round, instead of everyone being rank 1, everyone is
                        # at a very low rank (i.e., first-round flags are worth a bit less).
                        victim_rank = len(ctf.teams)

                    previous_captures = ctf.flag_captures[flag_id].count_before_round(
                        round_id
                    )
                    current_captures = (
                        ctf.flag_captures[flag_id].count_in_round(round_id)
                        + previous_captures
                    )

                    current_flag_value = (
                        1 + (1 / current_captures) ** 0.5 + (1 / victim_rank) ** 0.5
                    )

                    def delta(previous_flag_value):
                        return (
                            (current_flag_value - previous_flag_value)
                            / ctf.services[flag.service].flag_rate
                            * self.off_factor
                        )

                    if flag_id not in captured_flags:
                        for related_team in ctf.flag_captures[flag_id].by[RoundId(round_id-1)]:
                            previous_flag_value = (
                                1
                                + (1 / previous_captures) ** 0.5
                                + (1 / victim_rank) ** 0.5
                            )
                            attack = delta(previous_flag_value)
                            if related_team == "C4T BuT S4D":
                                print(round_id, related_team, flag.service, flag.owner, previous_captures, attack)
                            scoreboard[related_team] += Score.default(attack=attack)
                    captured_flags.add(flag_id)

                    attack = delta(0)
                    if team == "C4T BuT S4D":
                        print(round_id, flag.flag_id, attack)
                    scoreboard[team] += Score.default(attack=attack)

            # Compute defense scores
            for flag_id in captured_flags:
                flag = ctf.flags[flag_id]
                victim_sla = previous_slas[flag.round_id][(flag.owner, flag.service)]

                if self.defense_bug:
                    team_count = num_active_teams[round_id]
                else:
                    # This is what was probably intended
                    team_count = num_active_teams[flag.round_id]

                previous_captures = ctf.flag_captures[flag_id].count_before_round(
                    round_id
                )
                current_captures = (
                    ctf.flag_captures[flag_id].count_in_round(round_id)
                    + previous_captures
                )

                previous_damage = (previous_captures / team_count) ** 0.3 * victim_sla
                current_damage = (current_captures / team_count) ** 0.3 * victim_sla

                damage = (
                    (previous_damage - current_damage)
                    / ctf.services[flag.service].flag_rate
                    * self.def_factor
                )
                assert damage < 0 or (not victim_sla and damage <= 0)
                scoreboard[flag.owner] += Score.default(defense=damage)

        return scoreboard
