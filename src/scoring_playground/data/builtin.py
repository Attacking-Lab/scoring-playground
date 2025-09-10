import functools
import importlib.abc
import importlib.resources
import msgspec
import typing

from ..model import CTF, DataSource


class FileDataSource(DataSource):
    '''Base class for data sources that load data from files shipped with this package'''

    path: typing.ClassVar[importlib.abc.Traversable | None]

    @classmethod
    @functools.cache
    def read_bytes(cls: type[typing.Self]) -> bytes:
        '''Load the raw data that backs this data source as bytes'''
        if cls.path is None:
            raise AttributeError('read_bytes')
        return cls.path.read_bytes()

    @classmethod
    @functools.cache
    def read_str(cls: type[typing.Self], encoding: str | None = None) -> str:
        '''Load the raw data that backs this data source as a string, optionally with the specified encoding'''
        if cls.path is None:
            raise AttributeError('read_str')
        return cls.path.read_text(encoding)

    def __init_subclass__(cls: type[typing.Self], file_name: str | None = None) -> None:
        super().__init_subclass__()
        if file_name is None:
            cls.path = None
        else:
            cls.path = importlib.resources.files('scoring_playground.data').joinpath('raw').joinpath(file_name)


class JSONDataSource(FileDataSource):
    @classmethod
    @functools.partial(typing.cast, typing.Callable[[type[typing.Self]], CTF]) # Sorry. pyright does not like functools.cache here.
    @functools.cache
    def load(cls: type[typing.Self]) -> CTF:
        # By default, just try to load the JSON data with msgspec.
        # If you have other needs, override this.
        return msgspec.json.decode(cls.read_bytes(), type=CTF)
