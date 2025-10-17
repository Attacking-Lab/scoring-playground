import dataclasses
import copy
import collections
import math

from ..model import (
    CTF,
    RoundId,
    Score,
    Scoreboard,
    ScoringFormula,
    ServiceName,
    ServiceState,
    TeamName,
)


@dataclasses.dataclass(kw_only=True)
class ECSC2024(ScoringFormula):
    """The A/D scoring formula used in ECSC 2024"""

    @dataclasses.dataclass
    class ServiceScore:
        base: float
        attack: float = 0.0
        defense: float = 0.0
        rounds: int = 0
        up_rounds: int = 0

        def sum(self) -> float:
            return self.base + self.attack - self.defense

        def score(self) -> float:
            return max(0.0, self.sum())

        def total(self) -> float:
            if self.rounds == 0:
                return self.base
            return self.score() * self.up_rounds / self.rounds

    base: float = 5000.0
    scale: float = 15 * math.sqrt(5)
    norm: float = math.log(math.log(5)) / 12
    flag_validity: int = 6

    def evaluate(self, ctf: CTF) -> Scoreboard:
        for service in ctf.services.values():
            if len(service.flagstores) != 1:
                raise ValueError("Only one flagstore per service allowed")

        scores: dict[
            RoundId, dict[TeamName, dict[ServiceName, ECSC2024.ServiceScore]]
        ] = collections.defaultdict(
            lambda: collections.defaultdict(
                lambda: collections.defaultdict(
                    lambda: ECSC2024.ServiceScore(self.base)
                )
            )
        )

        for team in ctf.teams:
            for service in ctf.services:
                _ = scores[RoundId(-1)][team][service]

        flags_lost =collections.defaultdict(
                lambda: collections.defaultdict(
                    lambda: set()
                )
            )
        for round_id, round_data in ctf.enumerate():
            prev_scores = scores[RoundId(round_id - 1)]
            new_scores = scores[round_id] = copy.deepcopy(prev_scores)

            # Check for system errors
            skip_sla: dict[ServiceName, bool] = collections.defaultdict(lambda: True)
            for team, team_data in round_data.items():
                for service, service_status in team_data.service_states.items():
                    if service_status != ServiceState.ERROR:
                        skip_sla[service] = False
                        break

            for team, team_data in round_data.items():
                team_scores = new_scores[team]
                for service, service_status in team_data.service_states.items():
                    # Quirk: teams get sla if get_flag was not possible
                    can_getflag = False
                    min_related_round = max(0, round_id - self.flag_validity + 1)
                    for related_round in range(min_related_round, round_id):
                        related_round = ctf.rounds[related_round][team]
                        if len(related_round.flags_stored[service]) > 0:
                            can_getflag = True
                            break
                    if (
                        service_status == ServiceState.OK
                        or service_status == ServiceState.RECOVERING
                        and not can_getflag
                    ):
                        team_scores[service].up_rounds += 1
                    if service_status != ServiceState.ERROR:
                        team_scores[service].rounds += 1

                for flag_id in team_data.flags_captured:
                    flag = ctf.flags[flag_id]
                    # Quirk: scores taken at *end* of flag deployment round
                    assert round_id != flag.round_id
                    if flag.round_id == 0:
                        related_scores = scores[RoundId(-1)]
                    else:
                        related_scores = scores[RoundId(flag.round_id)]
                    assert flag.round_id != round_id
                    flags_lost[flag.owner][flag.service].add(team)
                    attacker_score = related_scores[team][flag.service].score()
                    victim_score = related_scores[flag.owner][flag.service].score()
                    score_delta = math.sqrt(attacker_score) - math.sqrt(victim_score)
                    delta = self.scale / (1 + math.exp(score_delta * self.norm))
                    new_scores[team][flag.service].attack += delta
                    new_scores[flag.owner][flag.service].defense += delta

            for team in round_data:
                for service, service_score in new_scores[team].items():
                    if service_score.sum() < 0:
                        service_score.defense += service_score.sum()

        scoreboard: Scoreboard = collections.defaultdict(Score.default)
        last_round = RoundId(len(ctf.rounds) - 1)
        for team_name, team_data in scores[last_round].items():
            up_rounds = 0
            checked_rounds = 0
            attack = defense = total = 0.0
            info = collections.defaultdict(lambda: {})
            for service in ctf.services:
                service_score = team_data[service]
                attack += service_score.attack
                defense += service_score.defense
                total += service_score.total()
                up_rounds += service_score.up_rounds
                checked_rounds += service_score.rounds
                info[service]["total"] = service_score.total()
                info[service]["attack"] = service_score.attack
                info[service]["defense"] = service_score.defense
                info[service]["delta_defense"] = service_score.defense - scores[RoundId(last_round-1)][team_name][service].defense
                info[service]["sla"] = service_score.up_rounds
                info[service]["lost"] = flags_lost[team_name][service]
            sla_factor = up_rounds / (checked_rounds or 1)
            scoreboard[team_name] = Score(
                total, attack=attack, defense=-defense, sla=sla_factor
            )
        return scoreboard
