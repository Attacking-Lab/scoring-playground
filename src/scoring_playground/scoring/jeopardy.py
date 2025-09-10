import dataclasses
import enum
import collections
import typing

from ..model import CTF, FlagId, FlagStoreId, RoundId, Score, Scoreboard, ScoringFormula, ServiceName, ServiceState, TeamName

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
    max: float = 10.0 # Target maximum/base score
    min: float = 1.0 # Target minimum score (may be ignored by individual formulas)

    sla: float = 5.0 # Value of the non-decaying SLA flags

    nop_team: TeamName | None = TeamName('NOP')

    def _jeopardy(self, solves: int, ctf: CTF) -> float:
        # Forcibly clamp the score to 0 - capturing flags should never be worth negative points.
        return max(
            self.jeopardy.value(solves, len(ctf.teams), self.alpha, self.beta, self.max, self.min),
            0
        )

    def evaluate(self, ctf: CTF) -> Scoreboard:
        if self.nop_team is not None and self.nop_team not in ctf.teams:
            raise KeyError(f'Configured NOP team {str(self.nop_team)!r} not found in the CTF data')

        # Pre-compute which teams exploited which teams on which service/flagstore/round combinations
        attacking_teams: typing.MutableMapping[
            tuple[RoundId, ServiceName, FlagStoreId],
            typing.MutableMapping[TeamName, set[FlagId]]
        ] = collections.defaultdict(lambda: collections.defaultdict(set))

        for round_id, round_data in ctf.enumerate():
            for team, team_data in round_data.items():
                for flag_id in team_data.flags_captured:
                    flag = ctf.flags[flag_id]
                    attacking_teams[(flag.round_id, flag.service, flag.flagstore)][team].add(flag_id)

        # Flags that we've already seen, in case of duplicates
        flags_seen: dict[TeamName, set[FlagId]] = { team: set() for team in ctf.teams }

        # Do the scoreboard calculations
        scoreboard: Scoreboard = collections.defaultdict(Score.default)
        for round_id, round_data in ctf.enumerate():
            # SLA flags:
            #   You gain a fixed SLA score for each flag available from the retention period,
            #   as long as the service is in the OK or RECOVERING state
            for team, team_data in round_data.items():
                sla = 0.0
                for service, state in team_data.service_states.items():
                    # TODO: We don't have information on _how many_ flags from the retention
                    # period are missing in RECOVERING, so try to work backwards (and assume
                    # that all flag stores are equally affected)
                    max_flags = min(round_id + 1, ctf.config.flag_retention)
                    if state == ServiceState.OK:
                        # All flags are there
                        present = max_flags
                    elif state == ServiceState.RECOVERING:
                        # All flags are there for the rounds that have been RECOVERING, but at least the oldest is missing
                        present = 1
                        for previous_round in range(round_id - 1, max(-1, round_id - ctf.config.flag_retention), -1):
                            if ctf.rounds[previous_round][team].service_states[service] != ServiceState.RECOVERING:
                                break
                            present += 1
                        present = min(present, max_flags)
                    else:
                        present = 0 # No flags for you in non-RECOVERING/OK states.
                    sla += self.sla * present * len(ctf.services[service].flagstores)
                scoreboard[team] += Score.default(sla=sla)

            # Defense flags
            #   For each flag that is still valid,
            #   for each attacking team,
            #   if you did not get exploited by that team
            #   you get points scaled by the number of teams that that team did not exploit
            # There are (teams - 2) * rounds * flagstores flags to capture here.
            # (If we restrict the definition of "attacking team" to those that actually capture flags
            # the flag count drops dramatically)
            # TODO: Where does the "that is still valid" go? Currently this is implicit in the data...
            # TODO: NOP team treatment here?
            # TODO: Note that this means that losing flags to a team who exploits _everyone_ is worse for
            #       you than losing flags to a team who exploits only a few people.
            #       This is somewhat counterintuitive.
            #       On the other hand, this rewards being one of a few to patch a difficult vulnerability
            #       that is being exploited.
            eligible_teams = len(ctf.teams) - (1 if self.nop_team is not None else 0) - 1
            for service, flagstore in ctf.flagstores:
                by_team = attacking_teams[(round_id, service, flagstore)]
                for attacker in ctf.teams:
                    if attacker == self.nop_team:
                        continue
                    # What is not getting exploited by this team worth?
                    value = self._jeopardy(eligible_teams - len(by_team[attacker]), ctf)
                    # Who did not get exploited?
                    for other in ctf.teams:
                        if other == attacker or other in by_team[attacker]:
                            continue
                        scoreboard[other] += Score.default(defense=value)


            # Attack flags
            #  For each flag that is still valid,
            #  if you capture that flag
            #  you get points scaled by how many teams captured that flag
            # There are (teams - 2) * rounds * flagstores flags to capture here.
            for team, team_data in round_data.items():
                attack = 0.0
                for flag_id in team_data.flags_captured:
                    if flag_id in flags_seen[team]:
                        continue
                    flags_seen[team].add(flag_id)
                    flag = ctf.flags[flag_id]
                    if flag.owner == self.nop_team or flag.owner == team:
                        continue
                    attack += self._jeopardy(ctf.flag_captures[flag_id].count, ctf)
                scoreboard[team] += Score.default(attack=attack)

        return scoreboard
