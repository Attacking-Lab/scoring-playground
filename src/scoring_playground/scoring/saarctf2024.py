import dataclasses
import collections
import typing

from ..model import CTF, RoundId, Score, Scoreboard, ScoringFormula, ServiceName, ServiceState, TeamName

@dataclasses.dataclass(kw_only=True)
class SaarCTF2024(ScoringFormula):
    '''This is the scoring formula from saarCTF 2024'''

    # NB: In the saarCTF gameserver, you can configure the validity period of the flags also.
    # We place this determination on the actual CTF data, however, since flags outside of the
    # validity period are often either not recorded, not submitted, or not even captured.

    off_factor: float = 1.0
    def_factor: float = 1.0
    sla_factor: float = 1.0
    nop_team: TeamName | None = TeamName('NOP')

    bug: bool = True # There is a bug in the gameserver's calculation of defense points, see below

    @staticmethod
    def _rank(scoreboard: Scoreboard, teams: typing.Sequence[TeamName]) -> typing.Mapping[TeamName, int]:
        ordered = sorted(((scoreboard[team], team) for team in teams), reverse=True)
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
            if score.combined > 0:
                counter += 1
        return ranking

    def evaluate(self, ctf: CTF) -> Scoreboard:
        if self.nop_team is not None and self.nop_team not in ctf.teams:
            raise KeyError(f'Configured NOP team {str(self.nop_team)!r} not found in the CTF data')

        scoreboard: Scoreboard = collections.defaultdict(Score.default)
        rankings: dict[RoundId, typing.Mapping[TeamName, int]] = {}
        previous_slas: dict[RoundId, typing.Mapping[tuple[TeamName, ServiceName], float]] = {}
        num_active_teams: dict[RoundId, int] = {}
        for round_id, round_data in ctf.enumerate():
            # Compute scoreboard rankings before this round
            rankings[round_id] = SaarCTF2024._rank(scoreboard, ctf.teams)
            if round_id == len(ctf.rounds) - 1:import pprint;pprint.pprint(sorted(rankings[round_id].items(), key=lambda p: (p[1],p[0]))) # XXX

            # Compute SLA scores and count teams
            sla: typing.MutableMapping[tuple[TeamName, ServiceName], float] = collections.defaultdict(float)
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
            previous_slas[round_id] = sla

            # Compute attack and defense scores
            for team, team_data in round_data.items():
                attack = defense = 0.0
                # Stealing the flag gives you points based on the number of times the flag
                # was captured. This is updated across rounds, so we can use the global count
                # and only compute it once.
                for flag_id in team_data.flags_captured:
                    flag = ctf.flags[flag_id]
                    if flag.owner == self.nop_team:
                        # These are not even submitted in saarCTF data.
                        continue
                    victim_rank = rankings[flag.round_id][flag.owner]
                    flag_value = 1 + (1 / ctf.flag_captures[flag_id].count) ** 0.5 + (1 / victim_rank) ** 0.5
                    attack += flag_value / ctf.services[flag.service].flag_rate * self.off_factor
                    if team == 'Bushwhackers':
                        import wcwidth
                        print('Flag: ' + flag.owner.ljust(40 + (len(flag.owner) - wcwidth.wcswidth(flag.owner))) + str(flag.round_id).ljust(4) + str(victim_rank).ljust(4) + str(ctf.flag_captures[flag_id].count).ljust(5) + str(flag_value).ljust(20) + '=> ' + str(attack)) # XXX

                # Similarly, defense score is only updated to the "newest" value, so we should be able
                # to do this globally. However, this is not actually correct, since the updates consider
                # the current round's number of active teams.
                # If we use the buggy calculation, we need to come back later and update the defense scores
                # when we have all the information.
                if not self.bug:
                    for flag_id in team_data.all_stored_flags.values():
                        flag = ctf.flags[flag_id]
                        victim_sla = previous_slas[flag.round_id][(flag.owner, flag.service)]

                        # This is what was probably intended
                        flag_value = (ctf.flag_captures[flag_id].count / num_active_teams[flag.round_id]) ** 0.3 * victim_sla
                        defense -= flag_value / ctf.services[flag.service].flag_rate * self.def_factor

                sla_total = sum(sla[(team, service)] for service in ctf.services)
                scoreboard[team] += Score.default(attack, defense, sla_total)

        if self.bug:
            for team in ctf.teams:
                defense = 0.0
                for round_id, round_data in ctf.enumerate():
                    team_data = round_data[team]
                    for flag_id in team_data.all_stored_flags.values():
                        flag = ctf.flags[flag_id]
                        victim_sla = previous_slas[flag.round_id][(flag.owner, flag.service)]
                        # Compute the iterative updates just for this flag
                        captures = 0
                        for captured_round, attackers in ctf.flag_captures[flag_id].by.items():
                            previous_damage = (captures / num_active_teams[captured_round]) ** 0.3 * victim_sla
                            captures += len(attackers)
                            damage = (captures / num_active_teams[captured_round]) ** 0.3 * victim_sla
                            defense -= (damage - previous_damage) / ctf.services[flag.service].flag_rate * self.def_factor
                scoreboard[team] += Score.default(defense=defense)

        return scoreboard
