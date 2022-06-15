from analyser.elements.node import Node


class File(Node):
    def __init__(self, name: str = None, offset: int = None, size: int = None) -> None:
        super().__init__(name)
        self.offset = offset
        self.size = size

    @property
    def offset(self) -> int:
        return self._offset

    @offset.setter
    def offset(self, value: int) -> None:
        try:
            self._offset = int(value)
        except ValueError:
            self._offset = None
        except TypeError:
            self._offset = None

    @property
    def size(self) -> int:
        return self._size

    @size.setter
    def size(self, value: int) -> None:
        try:
            self._size = int(value)
        except ValueError:
            self._size = None
        except TypeError:
            self._size = None

    def toDict(self) -> dict:
        data = super().toDict()
        data.update({"group": self.__class__.__name__,
                    "offset": self.offset, "size": self.size})
        return data
