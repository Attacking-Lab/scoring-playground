import abc
import collections
import dataclasses
import enum
import frozendict
import msgspec
import typing

from .util import defaults, immutable_cache

FlagId = typing.NewType('FlagId', int)
FlagStoreId = typing.NewType('FlagStoreId', int)
RoundId = typing.NewType('RoundId', int)
ServiceName = typing.NewType('ServiceName', str)
TeamName = typing.NewType('TeamName', str)


class ServiceState(enum.Enum):
    '''The state of a service'''
    OK = 'OK'
    RECOVERING = 'RECOVERING'
    MUMBLE = 'MUMBLE' # SLA violation (but team is active)
    OFFLINE = 'OFFLINE' # SLA violation (down/unreachable)
    ERROR = 'ERROR' # Checker-internal error


@dataclasses.dataclass
class Flag:
    '''Information about a flag'''
    flag_id: FlagId
    round_id: RoundId
    owner: TeamName
    service: ServiceName
    flagstore: FlagStoreId


@dataclasses.dataclass
class FlagCaptures:
    '''Information about how often a flag was captured, and by whom'''
    count: int = 0
    by: typing.MutableMapping[RoundId, typing.MutableSequence[TeamName]] = \
        dataclasses.field(default_factory=lambda: collections.defaultdict(list))

    def count_before_round(self, target_round_id: RoundId) -> int:
        return sum(len(attackers) for round_id, attackers in self.by.items() if round_id < target_round_id)

    def count_in_round(self, target_round_id: RoundId) -> int:
        return len(self.by.get(target_round_id, []))

    def count_including_round(self, target_round_id: RoundId) -> int:
        return sum(len(attackers) for round_id, attackers in self.by.items() if round_id <= target_round_id)


@dataclasses.dataclass(frozen=True)
class TeamRoundData:
    '''Information about one round for one team'''
    service_states: typing.Mapping[ServiceName, ServiceState]
    flags_stored: typing.Mapping[ServiceName, typing.Mapping[FlagStoreId, FlagId]]
    flags_captured: tuple[FlagId, ...]

    def __post_init__(self):
        # Freeze typing.Mapping (deserialized as dict, but it does not need to be mutable)
        object.__setattr__(self, 'service_states', frozendict.frozendict(self.service_states))
        object.__setattr__(self, 'flags_stored', frozendict.frozendict({
            service: frozendict.frozendict(by_flagstore)
            for service, by_flagstore in self.flags_stored.items()
        }))

    def iterate_stored_flags(self) -> typing.Iterator[FlagId]:
        return (flag_id for flagstore in self.flags_stored.values() for flag_id in flagstore.values())

    @property
    @immutable_cache
    def all_stored_flags(self) -> dict[tuple[ServiceName, FlagStoreId], FlagId]:
        return {
            (service, flagstore): flag_id
            for service, per_flagstore in self.flags_stored.items()
            for flagstore, flag_id in per_flagstore.items()
        }


@defaults(
    # "Normal" CTFs put one flag into each flagstore in each round
    flag_rate = lambda self: len(typing.cast(Service, self).flagstores)
)
@dataclasses.dataclass(slots=True, frozen=True)
class Service:
    '''Metadata about a service'''
    flagstores: tuple[FlagStoreId, ...]
    flag_rate: float | msgspec.UnsetType = msgspec.UNSET


@dataclasses.dataclass(frozen=True)
class Config:
    '''CTF configuration'''
    flag_validity: int
    flag_retention: int


@dataclasses.dataclass(frozen=True)
class CTF:
    '''A CTF'''
    services: typing.Mapping[ServiceName, Service]
    teams: tuple[TeamName, ...]
    rounds: tuple[typing.Mapping[TeamName, TeamRoundData], ...]
    config: Config

    def __post_init__(self):
        # Freeze typing.Mapping (deserialized as dict, but it does not need to be mutable)
        object.__setattr__(self, 'services', frozendict.frozendict(self.services))
        object.__setattr__(self, 'rounds', tuple(frozendict.frozendict(round_data) for round_data in self.rounds))

    def enumerate(self) -> typing.Iterator[tuple[RoundId, typing.Mapping[TeamName, TeamRoundData]]]:
        '''Iterate over the rounds of the CTF (basically, a correctly typed enumerate())'''
        return ((RoundId(round_id), round_data) for round_id, round_data in enumerate(self.rounds))

    @property
    @immutable_cache
    def flagstores(self) -> list[tuple[ServiceName, FlagStoreId]]:
        return [(name, flagstore) for name, service in self.services.items() for flagstore in service.flagstores]

    @property
    @immutable_cache
    def flags(self) -> dict[FlagId, Flag]:
        '''Collect all flags stored by the checker'''
        return {
            flag_id: Flag(flag_id, round_id, team, service, flagstore)
            for round_id, round_data in self.enumerate()
            for team, team_data in round_data.items()
            for service, per_flagstore in team_data.flags_stored.items()
            for flagstore, flag_id in per_flagstore.items()
        }

    @property
    @immutable_cache
    def flag_captures(self) -> typing.MutableMapping[FlagId, FlagCaptures]:
        '''Collects how often each flag was captured, and by whom'''
        captures: typing.MutableMapping[FlagId, FlagCaptures] = collections.defaultdict(FlagCaptures)
        for round_id, round_data in self.enumerate():
            for team, team_data in round_data.items():
                for flag_id in team_data.flags_captured:
                    captures[flag_id].count += 1
                    captures[flag_id].by[round_id].append(team)
        return captures

    def slice(self, from_round: int | None = None, to_round: int | None = None) -> typing.Self:
        '''Slices a subrange of the CTF (think rounds[from_round:to_round + 1])'''
        from_round = from_round if from_round is not None else 0
        to_round = (to_round + 1) if to_round is not None else len(self.rounds)
        sliced = dataclasses.replace(self, rounds=self.rounds[from_round:to_round])
        immutable_cache.reset(sliced)
        return sliced


@dataclasses.dataclass(slots=True, frozen=True, order=True)
class Score:
    '''A single score value, optionally with per-category subscores'''
    combined: float
    categories: typing.Mapping[str, float] = dataclasses.field(compare=False)

    def __add__(self, other: typing.Self) -> typing.Self:
        return type(self)(
            combined=self.combined + other.combined,
            categories={
                cat: self.categories[cat] + other.categories[cat]
                for cat in self.categories.keys() | other.categories.keys()
            }
        )

    @staticmethod
    def get_categories(scoreboard: 'Scoreboard') -> typing.Sequence[str]:
        keys = set()
        for score in scoreboard.values():
            keys |= score.categories.keys()
        return sorted(keys)

    @classmethod
    def default(cls: type[typing.Self], attack: float = 0.0, defense: float = 0.0, sla: float = 0.0) -> typing.Self:
        '''Most AD CTFs report scores as the sum of attack (ATK), defense (DEF) and SLA points.'''
        return cls(
            combined=attack + defense + sla,
            categories={
                'ATK': attack,
                'DEF': defense,
                'SLA': sla
            }
        )


type Scoreboard[S: Score] = typing.MutableMapping[TeamName, S]
'''The final scoreboard of a CTF'''


class ScoringFormula[S: Score](abc.ABC):
    '''A scoring formula'''
    @abc.abstractmethod
    def evaluate(self, ctf: CTF) -> Scoreboard[S]:
        '''Evaluates the scoring formula on a CTF'''


class DataSource(abc.ABC):
    '''A data source'''
    @classmethod
    @abc.abstractmethod
    def load(cls: type[typing.Self]) -> CTF:
        '''Loads the CTF data'''
