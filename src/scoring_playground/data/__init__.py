from .builtin import JSONDataSource
from ..model import DataSource


class SaarCTF2024(JSONDataSource, file_name='saarctf2024.json'):
    '''CTF data from saarCTF 2024'''

class ENOWARS2024(JSONDataSource, file_name='enowars2024.json'):
    '''CTF data from saarCTF 2024'''


sources: list[type[DataSource]] = [
    ENOWARS2024,
    SaarCTF2024,
]
__all__ = ['sources', 'ENOWARS2024', 'SaarCTF2024']

