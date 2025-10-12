from .builtin import JSONDataSource
from ..model import DataSource


class SaarCTF2024(JSONDataSource, file_name="saarctf2024.json"):
    """CTF data from saarCTF 2024"""


class ENOWARS2024(JSONDataSource, file_name="enowars2024.json"):
    """CTF data from ENOWARS (8) 2024"""


class FaustCTF2024(JSONDataSource, file_name="faustctf2024.json"):
    """CTF data from FaustCTF 2024"""


class ECSC2024(JSONDataSource, file_name="ecsc2024.json"):
    """CTF data from ECSC 2024"""


class ECSC2025(JSONDataSource, file_name="ecsc2025.json"):
    """CTF data from ECSC 2025"""


sources: list[type[DataSource]] = [
    ENOWARS2024,
    SaarCTF2024,
    FaustCTF2024,
    ECSC2024,
    ECSC2025,
]
__all__ = [
    "sources",
    "ENOWARS2024",
    "SaarCTF2024",
    "FaustCTF2024",
    "ECSC2024",
    "ECSC2025",
]
