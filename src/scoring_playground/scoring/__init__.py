from .saarctf2024 import SaarCTF2024
from ..model import ScoringFormula

formulas: list[type[ScoringFormula]] = [
    SaarCTF2024,
]
__all__ = ['formulas', 'SaarCTF2024']

