import dataclasses
import enum
import collections
import typing

from ..model import CTF, FlagId, RoundId, Score, Scoreboard, ScoringFormula, ServiceName, ServiceState, TeamName

class Wrapper:
    '''Wrapper for a jeopardy formula'''
    # This is required because enum.Enum.__members__ won't work otherwise
    def __init__(self, implementation: typing.Callable[[int, int, float | None, float | None, float, float], float]):
        self.implementation = implementation
    def __call__(self, solves: int, teams: int, alpha: float | None, beta: float | None, max_score: float, min_score: float) -> float:
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
        lambda solves, teams, alpha, beta, max_score, min_score:
            max_score * (min_score / max_score) ** ((max(0, solves - 1) / max(1, teams - 1)) ** or_default(alpha, 0.705))
            + assert_none(beta, 'beta')
    )
    # "Normal" decaying formula used e.g. by 34C3 CTF and CSCG
    CSCG = Wrapper(
        lambda solves, _teams, alpha, beta, max_score, min_score:
            min_score + (max_score - min_score) / (1 + (max(0, solves - 1) / or_default(beta, 11.92201)) ** or_default(alpha, 1.206069))
    )
    # "Normal" decaying formula used e.g. by hxp CTF
    hxp = Wrapper(
        lambda solves, _teams, alpha, beta, max_score, _min_score:
            max_score * min(1, or_default(alpha, 10.0) / (or_default(beta, 9.0) + solves))
    )


@dataclasses.dataclass(kw_only=True)
class Jeopardy(ScoringFormula):
    '''This is a jeopardy-based scoring formula'''

    jeopardy: JeopardyFormula
    alpha: float | None = None # Formula-specfic parameters
    beta: float | None = None # Formula-specific parameters
    max: float = 1000.0 # Target maximum/base score
    min: float = 100.0 # Target minimum score (may be ignored by individual formulas)

    sla: float = 500.0 # Value of the non-decaying SLA flags

    nop_team: TeamName | None = TeamName('NOP')

    def _jeopardy(self, solves: int, ctf: CTF) -> float:
        return self.jeopardy.value(solves, len(ctf.teams), self.alpha, self.beta, self.max, self.min)

    def evaluate(self, ctf: CTF) -> Scoreboard:
        if self.nop_team is not None and self.nop_team not in ctf.teams:
            raise KeyError(f'Configured NOP team {str(self.nop_team)!r} not found in the CTF data')

        raise NotImplementedError()
        #scoreboard: Scoreboard = collections.defaultdict(Score.default)
        #for round_id, round_data in ctf.enumerate():
        #    # SLA flags:
        #    #  You gain a fixed SLA score for each flag available from the retention period, as long as the service
        #    #  is in the OK or RECOVERING state
        #    for team, team_data in round_data.items():
        #        sla = 0.0
        #        for service, state in team_data.service_states.items():
        #            # TODO: We don't have information on _how many_ flags from the retention period are missing in RECOVERING,
        #            # so try to work back from the next OK (and assume that all flag stores are equally affected)
        #            max_flags = min(round_id + 1, ctf.config.flag_retention)
        #            if state == ServiceState.OK:
        #                # All flags are there
        #                present = max_flags
        #            elif state == ServiceState.RECOVERING:
        #                # All flags are there for the rounds that have been RECOVERING, but at least the oldest is missing
        #                present = 1
        #                for previous_round in range(round_id - 1, max(-1, round_id - ctf.config.flag_retention), -1):
        #                    if ctf.rounds[previous_round][team].service_states[service] != ServiceState.RECOVERING
        #                        break
        #                    present += 1
        #                present = min(present, max_flags)
        #            else:
        #                present = 0 # No flags for you in non-RECOVERING/OK states.
        #            sla += self.sla * present * len(ctf.services[service].flagstores)
        #        scoreboard[team] += Score.default(sla=sla)

        #    # Defense flags
        #    #  For each flag that is still valid,
        #    #  for each attacking team,
        #    #  you get points scaled by the number of teams that that team did not exploit
