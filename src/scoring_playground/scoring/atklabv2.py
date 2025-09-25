import dataclasses
import enum
import collections
import typing

from msgspec import UNSET

from ..model import CTF, FlagStoreId, RoundId, Score, Scoreboard, ScoringFormula, ServiceName, ServiceState, TeamName

class Wrapper:
    '''Wrapper for a jeopardy formula'''
    # This is required because enum.Enum.__members__ won't work otherwise
    def __init__(self, implementation: typing.Callable[[float, int, float | None, float | None, float, float], float]):
        self.implementation = implementation
    def __call__(self, solves: float, teams: int, alpha: float | None, beta: float | None, max_score: float, min_score: float) -> float:
        return self.implementation(solves, teams, alpha, beta, max_score, min_score)


def assert_none(parameter: float | None, label: str) -> float:
    if parameter is not None:
        raise RuntimeError(f'Parameter {label} is not used by the selected jeopardy formula, and should not be configured')
    return 0.0

def assert_value(parameter: float | None, label: str) -> float:
    if parameter is None:
        raise RuntimeError(f'Parameter {label} is required by the selected jeopardy formula')
    return parameter

def or_default(parameter: float | None, default: float) -> float:
    return parameter if parameter is not None else default


class JeopardyFormula(enum.Enum):
    '''Various jeopardy scoring formulas'''
    def __str__(self):
        return self.name
    # Exponential formula for fixed team counts used at DHM (2025: alpha = 0.705, 2024: alpha = 1.7)
    DHM = Wrapper(
        lambda solves, teams, alpha, beta, min_score, max_score:
            max_score * (min_score / max_score) ** ((max(0, solves - 1) / max(1, teams - 1)) ** or_default(alpha, 0.705))
            + assert_none(beta, 'beta')
    )
    # "Normal" decaying formula used e.g. by 34C3 CTF and CSCG
    CSCG = Wrapper(
        lambda solves, _teams, alpha, beta, min_score, max_score:
            min_score + (max_score - min_score) / (1 + (max(0, solves - 1) / or_default(beta, 11.92201)) ** or_default(alpha, 1.206069))
    )
    # "Normal" decaying formula used e.g. by hxp CTF
    hxp = Wrapper(
        lambda solves, _teams, alpha, beta, _min_score, max_score:
            max_score * min(1, or_default(alpha, 10.0) / (or_default(beta, 9.0) + solves))
    )
    # "Normal" decaying formula used e.g. by ECSC 2025
    ECSC2025 = Wrapper(
        lambda solves, teams, _alpha, _beta, min_score, max_score:
            max(int(max_score * ((teams * 3 / 4) / (teams * 3 / 4 - 1 + max(solves, 1))) ** 3), min_score)
    )


class AttackerMode(enum.Enum):
    '''How to determine which teams are attacking'''
    Everyone = 0 # Everyone is attacking all the time
    Successful = 1 # Only someone who actually gets a flag from this round is attacking
    Scaled = 2 # Same as `Successful`, but scale the "value" of the attackers up to the full team count


@dataclasses.dataclass(kw_only=True)
class ATKLABv2(ScoringFormula):
    '''This is a jeopardy-based scoring formula'''

    jeopardy: JeopardyFormula
    alpha: float | None = None # Formula-specfic parameters
    beta: float | None = None # Formula-specific parameters
    base: float = 10.0 # Base challenge value / scaling factor
    min: float = 1.0 # Minimum value per challenge

    attackers: AttackerMode = AttackerMode.Everyone

    nop_team: TeamName | None = TeamName('NOP')

    def _jeopardy(self, solves: float, ctf: CTF) -> float:
        # Forcibly clamp the score to 0 - capturing flags should never be worth negative points.
        # Note that the solve count is a float rather than an int because all formulas allow
        # interpolation and it could be useful in some places.
        return max(
            self.jeopardy.value(solves, len(ctf.teams), self.alpha, self.beta, self.min, self.base),
            0
        )

    def evaluate(self, ctf: CTF) -> Scoreboard:
        if self.nop_team is not None and self.nop_team not in ctf.teams:
            raise KeyError(f'Configured NOP team {str(self.nop_team)!r} not found in the CTF data')

        if ctf.config.flag_retention is UNSET:
            raise KeyError(f'No flag retention period defined in CTF data')

        # Pre-compute victims for each service/flagstore/attacker,
        # attributed back to the round in which the stolen flag was deployed
        attacked_teams: typing.MutableMapping[
            tuple[RoundId, ServiceName, FlagStoreId],
            typing.MutableMapping[TeamName, set[TeamName]]
        ] = collections.defaultdict(lambda: collections.defaultdict(set))
        for round_id, round_data in ctf.enumerate():
            for team, team_data in round_data.items():
                for flag_id in team_data.flags_captured:
                    flag = ctf.flags[flag_id]
                    if flag.owner == team or flag.owner == self.nop_team:
                        continue
                    attacked_teams[(flag.round_id, flag.service, flag.flagstore)][team].add(ctf.flags[flag_id].owner)

        # Do the scoreboard calculations
        scoreboard: Scoreboard = collections.defaultdict(Score.default)
        for round_id, round_data in ctf.enumerate():
            # SLA flags:
            #   You gain a fixed SLA score for each flag available from the
            #   retention period, as long as the status is OK or RECOVERING.
            for team, team_data in round_data.items():
                sla = 0.0
                for service, state in team_data.service_states.items():
                    flagstores = len(ctf.services[service].flagstores)
                    max_rounds = min(round_id + 1, ctf.config.flag_retention)
                    max_flags = max_rounds * flagstores
                    if state == ServiceState.OK:
                        present = max_flags
                    elif state == ServiceState.RECOVERING:
                        present = 1
                        # XXX: We estimate here that flags which were present in
                        #      previous rounds are still present and returned,
                        #      because the IL does not encode flags retrieved (yet).
                        for previous_round in reversed(range(max(0, round_id - ctf.config.flag_retention), round_id - 1)):
                            if ctf.rounds[previous_round][team].service_states[service] != ServiceState.RECOVERING:
                                break
                            present += 1
                        present = min(present, max_flags)
                    else:
                        present = 0
                    sla += self.base * present / max_flags * flagstores
                scoreboard[team] += Score.default(sla=sla)

            # Attack flags:
            #   For each flag that is still valid, if you capture that flag
            #   you get points scaled by how many teams captured that flag.
            for team, team_data in round_data.items():
                attack = 0.0
                for flag_id in team_data.flags_captured:
                    flag = ctf.flags[flag_id]
                    if flag.owner == team:
                        continue
                    attack += self._jeopardy(ctf.flag_captures[flag_id].count, ctf)
                scoreboard[team] += Score.default(attack=attack)

            # Estimate the number of playing teams
            online_cnt = 0
            for team, team_data in round_data.items():
                if any(s != ServiceState.OFFLINE for s in team_data.service_states):
                    online_cnt += 1

            # Defense flags:
            #   For each flag that is still valid, for each attacking team,
            #   if you did not get exploited by that team,
            #   you get points scaled by the number of teams that that team did not exploit.
            max_victims = online_cnt - (1 if self.nop_team is not None else 0) - 1
            for service, flagstore in ctf.flagstores:
                victims_of = attacked_teams[(round_id, service, flagstore)]

                match self.attackers:
                    case AttackerMode.Everyone:
                        attackers = ctf.teams
                    case AttackerMode.Successful | AttackerMode.Scaled:
                        attackers = [team for team in ctf.teams if len(victims_of[team]) > 0]

                for attacker in attackers:
                    if attacker == self.nop_team:
                        continue
                    not_exploited = max_victims - len(victims_of[attacker])
                    value = self._jeopardy(not_exploited, ctf)
                    if self.attackers == AttackerMode.Scaled:
                        value *= max_victims / len(attackers)
                    for other, other_data in round_data.items():
                        if other == attacker or other in victims_of[attacker]:
                            continue
                        if other_data.service_states[service] not in (ServiceState.OK, ServiceState.RECOVERING):
                            continue
                        scoreboard[other] += Score.default(defense=value)

        return scoreboard
