from .jeopardy import Jeopardy
from .saarctf2024 import SaarCTF2024
from ..model import ScoringFormula

formulas: list[type[ScoringFormula]] = [
    Jeopardy,
    SaarCTF2024,
]
__all__ = ['formulas', 'Jeopardy', 'SaarCTF2024']

