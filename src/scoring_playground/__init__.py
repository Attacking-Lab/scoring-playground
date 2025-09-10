import argparse
import dataclasses
import msgspec
import sys
import tabulate
import typing
import warnings

from .data import sources
from .scoring import formulas
from .model import Score

def __main__() -> None:
    data_sources = sorted(source.__name__ for source in sources)
    scoring_formulas = sorted(formula.__name__ for formula in formulas)

    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--data', help='Selects the CTF data source', choices=data_sources, required=True)
    parser.add_argument('--formula', help='Selects the scoring formula', choices=scoring_formulas, required=True)
    parser.add_argument('--output-format', help='Output format', choices=('json', 'table'), default='table')
    parser.add_argument('--from-round', help='Assume the CTF started in this round (this round is included in scoring)', type=int)
    parser.add_argument('--to-round', help='Assume the CTF ended in this round (this round is included in scoring)', type=int)

    base, remaining_args = parser.parse_known_args()
    source = next(source for source in sources if source.__name__ == base.data)
    formula = next(formula for formula in formulas if formula.__name__ == base.formula)

    config_parser = argparse.ArgumentParser(allow_abbrev=False)

    def base_type_of(type_hint: typing.Any, *, location: str | None = None) -> type:
        if type_hint is dataclasses.MISSING:
            warnings.warn('Missing type hint' + (f' for {location}' if location is not None else '') + ', falling back to str')
            return str
        elif typing.get_origin(type_hint) is typing.Union:
            union_types = set(typing.get_args(type_hint))
            union_types.remove(type(None))
            if len(union_types) > 1:
                warnings.warn('Cannot handle multi-type union {union_types}' + (f' for {location}' if location is not None else '') + ', falling back to str')
                return str
            if not union_types:
                return type(None)
            return base_type_of(union_types.pop(), location=location)
        elif isinstance(type_hint, type):
            return type_hint
        else:
            warnings.warn('Cannot handle type hint {type_hint}' + (f' for {location}' if location is not None else '') + ', falling back to str')
            return str

    def build_options_parser(root: argparse.ArgumentParser, title: str, ty: type):
        if not dataclasses.is_dataclass(source):
            return

        fields = [field for field in dataclasses.fields(ty) if not field.name.startswith('_')]
        if not fields:
            return

        hints = typing.get_type_hints(ty)
        subparser = root.add_argument_group(title)
        for field in fields:
            expected_type = hints.get(field.name, dataclasses.MISSING)
            argument_type = base_type_of(expected_type, location=f'{ty.__name__}.{field.name}')

            if argument_type is bool:
                action = argparse.BooleanOptionalAction
            elif argument_type is list:
                action = 'append'
            else:
                action = 'store'

            if field.default_factory is not dataclasses.MISSING:
                required = False
                help_text = '(default: dynamic)'
            elif field.default is not dataclasses.MISSING:
                required = False
                help_text = f'(default: {field.default!r})'
            else:
                required = True
                help_text = None

            subparser.add_argument(
                '--' + field.name.replace('_', '-'),
                action=action,
                help=help_text,
                required=required,
                type=argument_type,
            )

    def configure[T](ty: type[T], options: argparse.Namespace) -> T:
        if not dataclasses.is_dataclass(source):
            return ty()
        return ty(**{ field.name: getattr(options, field.name) for field in dataclasses.fields(source) if field.name in options })


    build_options_parser(config_parser, 'Data source options', source)
    build_options_parser(config_parser, 'Scoring formula options', formula)

    options = config_parser.parse_args(remaining_args)

    data_source = configure(source, options)
    scoring_formula = configure(formula, options)

    ctf = data_source.load().slice(base.from_round, base.to_round)
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
