from .atklabv1 import ATKLABv1
from .atklabv2 import ATKLABv2
from .saarctf2024 import SaarCTF2024
from .ecsc2025 import ECSC2025
from ..model import ScoringFormula

formulas: list[type[ScoringFormula]] = [
    ATKLABv1,
    ATKLABv2,
    SaarCTF2024,
    ECSC2025,
]
__all__ = ["formulas", "ATKLABv1", "ATKLABv2", "SaarCTF2024", "ECSC2025"]
