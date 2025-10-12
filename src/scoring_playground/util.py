import dataclasses
import functools
import msgspec
import typing


def defaults[Extends](
    **exts: typing.Callable[[Extends], typing.Any],
) -> typing.Callable[[type[Extends]], type[Extends]]:
    """Assigns defaults to None-valued fields in a dataclass"""

    def defaults_decorator(cls: type[Extends]) -> type[Extends]:
        if not dataclasses.is_dataclass(cls):
            raise TypeError(f"Cannot assign defaults in non-dataclass type {cls}")

        field_names = set()
        for field in dataclasses.fields(cls):
            field_names.add(field.name)

        for ext in exts:
            if ext not in field_names:
                raise AttributeError(f"{cls} has no attribute {ext}")

        post_init = getattr(cls, "__post_init__", None)
        wrapper = functools.wraps(post_init) if post_init else (lambda fn: fn)

        @wrapper
        def new_post_init(self: Extends) -> None:
            for key in exts:
                if getattr(self, key) is msgspec.UNSET:
                    # Bypass `frozen=true`
                    object.__setattr__(self, key, exts[key](self))

            if post_init:
                return post_init(self)

        setattr(cls, "__post_init__", new_post_init)
        return cls

    return defaults_decorator


@dataclasses.dataclass
class ImmutableCache:
    attribute: str = "__immutable_cache__"

    def __call__[T, U](
        self, function: typing.Callable[[T], U]
    ) -> typing.Callable[[T], U]:
        """Caches the function results under the assumption that `self` never changes"""

        @functools.wraps(function)
        def caching_wrapper(obj: T) -> U:
            if not hasattr(obj, self.attribute):
                cache: dict[str, typing.Any] = {}
                object.__setattr__(obj, self.attribute, cache)
            else:
                cache = getattr(obj, self.attribute)
            if function.__qualname__ not in cache:
                cache[function.__qualname__] = function(obj)
            return typing.cast(U, cache[function.__qualname__])

        return caching_wrapper

    def reset(self, obj: object) -> None:
        if hasattr(obj, self.attribute):
            object.__delattr__(obj, self.attribute)


immutable_cache = ImmutableCache()
