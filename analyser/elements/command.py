from analyser.elements.node import Node


class Command(Node):
    def __init__(self, name: str = None, args: str = None) -> None:
        super().__init__(name)
        self.args = args

    @property
    def args(self) -> str:
        return self._args

    @args.setter
    def args(self, value: str) -> None:
        try:
            self._args = str(value)
        except ValueError:
            self._args = None
        except TypeError:
            self._args = None

    def toDict(self) -> dict:
        data = super().toDict()
        data.update({"group": self.__class__.__name__,"args":self.args})
        return data