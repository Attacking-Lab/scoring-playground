from .atklabv2 import ATKLABv2
from .saarctf2024 import SaarCTF2024
from ..model import ScoringFormula

formulas: list[type[ScoringFormula]] = [
    ATKLABv2,
    SaarCTF2024,
]
__all__ = ['formulas', 'ATKLABv2', 'SaarCTF2024']

