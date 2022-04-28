from json import dumps
import uuid


class Node():
    def __init__(self, name):
        super().__init__()
        self._uid = uuid.uuid1()
        self.name = name
        self.children = []

    @property
    def uid(self):
        return self._uid

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        try:
            self._name = str(value)
        except ValueError:
            self._name = None
        except TypeError:
            self._name = None

    @property
    def children(self):
        return self._children

    @children.setter
    def children(self, value):
        if not(isinstance(value, list)):
            raise TypeError("chidren must be a list")
        for elt in value:
            if not(isinstance(elt, Node)):
                raise TypeError(
                    "All elements in children must be a Node object")
        self._children = value

    def toDict(self) -> dict:
        return {"type":self.__class__.__name__,"name": self.name, "uid": str(self.uid), "children": [elt.toDict() for elt in self.children]}
