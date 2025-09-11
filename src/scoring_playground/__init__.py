import argparse
import dataclasses
import enum
import msgspec
import sys
import tabulate
import types
import typing
import warnings

from .data import sources
from .scoring import formulas
from .model import Score

def __main__() -> None:
    data_sources = sorted(source.__name__ for source in sources)
    scoring_formulas = sorted(formula.__name__ for formula in formulas)

    help_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    help_parser.add_argument('-h', '--help', action='store_true')
    help_parser.add_argument('--data')
    help_parser.add_argument('--formula')
    help_args, _ = help_parser.parse_known_args()

    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--data', help='Selects the CTF data source', choices=data_sources, required=True)
    parser.add_argument('--formula', help='Selects the scoring formula', choices=scoring_formulas, required=True)
    parser.add_argument('--output-format', help='Output format', choices=('json', 'table'), default='table')
    parser.add_argument('--from-round', help='Assume the CTF started in this round (this round is included in scoring)', type=int)
    parser.add_argument('--to-round', help='Assume the CTF ended in this round (this round is included in scoring)', type=int)

    config_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False, usage=argparse.SUPPRESS)

    def base_type_of(type_hint: typing.Any, *, location: str | None = None) -> tuple[type, bool]: # (type, allowed to be none?)
        if type_hint is dataclasses.MISSING:
            warnings.warn('Missing type hint' + (f' for {location}' if location is not None else '') + ', falling back to str')
            return str, False
        elif typing.get_origin(type_hint) in (types.UnionType, typing.Union):
            union_types = set(typing.get_args(type_hint))
            may_be_none = type(None) in union_types or None in union_types
            union_types -= { type(None), None }
            if len(union_types) > 1:
                warnings.warn(f'Cannot handle multi-type union {union_types}' + (f' for {location}' if location is not None else '') + ', falling back to str')
                return str, may_be_none
            if not union_types:
                raise TypeError('Union type contains only None')
            base_type, base_may_be_none = base_type_of(union_types.pop(), location=location)
            return base_type, base_may_be_none or may_be_none
        elif isinstance(type_hint, type):
            return type_hint, False
        elif isinstance(type_hint, typing.NewType):
            return base_type_of(type_hint.__supertype__, location=location)
        else:
            warnings.warn(f'Cannot handle type hint {type_hint}' + (f' for {location}' if location is not None else '') + ', falling back to str')
            return str, False

    def build_options_parser(root: argparse.ArgumentParser, title: str, ty: type):
        if not dataclasses.is_dataclass(ty):
            return

        fields = [field for field in dataclasses.fields(ty) if not field.name.startswith('_')]
        if not fields:
            return

        hints = typing.get_type_hints(ty)
        subparser = root.add_argument_group(title)
        for field in fields:
            expected_type = hints.get(field.name, dataclasses.MISSING)
            argument_type, may_be_none = base_type_of(expected_type, location=f'{ty.__name__}.{field.name}')

            action = 'store'
            if argument_type is bool:
                action = argparse.BooleanOptionalAction

            choices = None
            if issubclass(argument_type, enum.Enum):
                choices = argument_type.__members__.values()
                argument_type = lambda key, enum_type=argument_type: enum_type[key] if key in enum_type.__members__ else key

            required = False
            help_text = None
            if field.default_factory is not dataclasses.MISSING:
                help_text = '(default: dynamic)'
            elif field.default is not dataclasses.MISSING:
                if field.default is None:
                    help_text = '(default: unset)'
                else:
                    help_text = f'(default: {field.default!r})'
            else:
                required = True

            if may_be_none:
                group = subparser.add_mutually_exclusive_group()
                group.add_argument(
                    '--no-' + field.name.replace('_', '-'),
                    action='store_const',
                    const=None,
                    dest=field.name,
                )
            else:
                group = subparser
            group.add_argument(
                '--' + field.name.replace('_', '-'),
                action=action,
                choices=choices,
                default=argparse.SUPPRESS,
                dest=field.name,
                help=help_text,
                required=required,
                type=argument_type,
            )

    def configure[T](ty: type[T], options: argparse.Namespace) -> T:
        if not dataclasses.is_dataclass(ty):
            return ty()
        return ty(**{
            field.name: getattr(options, field.name)
            for field in dataclasses.fields(ty)
            if field.name in options
        })

    if help_args.help:
        source = next((source for source in sources if source.__name__ == help_args.data), None)
        formula = next((formula for formula in formulas if formula.__name__ == help_args.formula), None)
        if source is not None:
            build_options_parser(config_parser, 'data source options', source)
        if formula is not None:
            build_options_parser(config_parser, 'scoring formula options', formula)

        # Print the main help and the config parser help, but strip out the (empty) config parser usage
        parser.print_help()
        print()
        config_parser.print_help()
        parser.exit()

    base, remaining_args = parser.parse_known_args()
    source = next(source for source in sources if source.__name__ == base.data)
    formula = next(formula for formula in formulas if formula.__name__ == base.formula)

    build_options_parser(config_parser, 'data source options', source)
    build_options_parser(config_parser, 'scoring formula options', formula)

    options = config_parser.parse_args(remaining_args)

    data_source = configure(source, options)
    scoring_formula = configure(formula, options)

    ctf = data_source.load().slice(base.from_round, base.to_round)
    for message in ctf.config.messages:
        print('\x1b[33m' + message + '\x1b[0m', file=sys.stderr)
    scoreboard = scoring_formula.evaluate(ctf)

    match base.output_format:
        case 'json':
            sys.stdout.buffer.write(msgspec.json.encode(scoreboard))
        case 'table':
            keys = Score.get_categories(scoreboard)
            data = [
                (team, score.combined, *(score.categories[key] for key in keys))
                for team, score in sorted(scoreboard.items(), key=lambda item: item[1].combined, reverse=True)
            ]
            print(tabulate.tabulate(data, headers=('Team', 'Score', *keys), tablefmt='simple_grid'))
