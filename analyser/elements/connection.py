from threading import local
from analyser.elements.node import Node


class Connection(Node):
    def __init__(self, name: str = None, foreign_addr: str = None, foreign_port: int = None, local_addr: str = None, local_port: int = None, offset: int = None, owner: str = None, pid: int = None, protocol: str = None, state: str = None) -> None:
        super().__init__(name)
        self.foreign_addr = foreign_addr
        self.foreign_port = foreign_port
        self.local_addr = local_addr
        self.local_port = local_port
        self.offset = offset
        self.owner = owner
        self.pid = pid
        self.protocol = protocol
        self.state = state

    @property
    def foreign_addr(self) -> str:
        return self._foreign_addr

    @foreign_addr.setter
    def foreign_addr(self, value: str) -> None:
        try:
            self._foreign_addr = str(value)
        except ValueError:
            self._foreign_addr = None
        except TypeError:
            self._foreign_addr = None

    @property
    def foreign_port(self) -> int:
        return self._foreign_port

    @foreign_port.setter
    def foreign_port(self, value: int) -> None:
        try:
            self._foreign_port = int(value)
        except ValueError:
            self._foreign_port = None
        except TypeError:
            self._foreign_port = None

    @property
    def local_addr(self) -> str:
        return self._local_addr

    @local_addr.setter
    def local_addr(self, value: str) -> None:
        try:
            self._local_addr = str(value)
        except ValueError:
            self._local_addr = None
        except TypeError:
            self._local_addr = None

    @property
    def local_port(self) -> int:
        return self._local_port

    @local_port.setter
    def local_port(self, value: int) -> None:
        try:
            self._local_port = int(value)
        except ValueError:
            self._local_port = None
        except TypeError:
            self._local_port = None

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
    def owner(self) -> str:
        return self._owner

    @owner.setter
    def owner(self, value: str) -> None:
        try:
            self._owner = str(value)
        except ValueError:
            self._owner = None
        except TypeError:
            self._owner = None

    @property
    def pid(self) -> int:
        return self._pid

    @pid.setter
    def pid(self, value: int) -> None:
        try:
            self._pid = int(value)
        except ValueError:
            self._pid = None
        except TypeError:
            self._pid = None

    @property
    def protocol(self) -> str:
        return self._protocol

    @protocol.setter
    def protocol(self, value: str) -> None:
        try:
            self._protocol = str(value)
        except ValueError:
            self._protocol = None
        except TypeError:
            self._protocol = None

    @property
    def state(self) -> str:
        return self._state

    @state.setter
    def state(self, value: str) -> None:
        try:
            self._state = str(value)
        except ValueError:
            self._state = None
        except TypeError:
            self._state = None

    def toDict(self) -> dict:
        data = super().toDict()
        data.update({"group": self.__class__.__name__, "foreign_addr": self.foreign_addr, "foreign_port": self.foreign_port, "local_addr": self.local_addr,
                    "local_port": self.local_port, "offset": self.offset, "owner": self.owner, "pid": self.pid, "protocol": self.protocol, "state": self.state})
        return data
