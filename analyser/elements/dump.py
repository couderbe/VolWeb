from hashlib import md5, sha1, sha256
from analyser.elements.node import Node
from analyser.elements.process import Process


class Dump(Node):
    def __init__(self, name: str = None, md5: str = None, sha1: str = None, sha256: str = None) -> None:
        super().__init__(name)
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256

    def processes(self) -> 'list[Process]':
        return [elt for elt in self.children if isinstance(elt, Process)]

    @property
    def md5(self) -> str:
        return self._md5

    @md5.setter
    def md5(self, value: str) -> None:
        try:
            self._md5 = str(value)
        except ValueError:
            self._md5 = None
        except TypeError:
            self._md5 = None

    @property
    def sh1(self) -> str:
        return self._sh1

    @sh1.setter
    def sh1(self, value: str) -> None:
        try:
            self._sh1 = str(value)
        except ValueError:
            self._sh1 = None
        except TypeError:
            self._sh1 = None

    @property
    def sha256(self) -> str:
        return self._sha256

    @sha256.setter
    def sha256(self, value: str) -> None:
        try:
            self._sha256 = str(value)
        except ValueError:
            self._sha256 = None
        except TypeError:
            self._sha256 = None

    def toDict(self) -> dict:
        data = super().toDict()
        data.update({"group": self.__class__.__name__,
                    "md5": self.md5, "sha1": self.sha1, "sha256": self.sha256})
        return data
