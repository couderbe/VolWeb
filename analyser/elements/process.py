from datetime import datetime
from json import dumps
from analyser.elements.handle import Handle
from analyser.elements.node import Node
from analyser.elements.thread import Thread


class Process(Node):
    def __init__(self, name: str = None, pid: int = None, ppid: int = None, sessionId: int = None, wow64: bool = None, createTime: datetime = None, exitTime: datetime = None) -> None:
        super().__init__(name)
        self.pid = pid
        self.ppid = ppid
        self.sessionId = sessionId
        self.wow64 = wow64
        self.createTime = createTime
        self.exitTime = exitTime

    @property
    def pid(self):
        return self._pid

    @pid.setter
    def pid(self, value):
        try:
            self._pid = int(value)
        except ValueError:
            self._pid = None
        except TypeError:
            self._pid = None

    @property
    def ppid(self):
        return self._ppid

    @ppid.setter
    def ppid(self, value):
        try:
            self._ppid = int(value)
        except ValueError:
            self._ppid = None
        except TypeError:
            self._ppid = None

    @property
    def sessionId(self):
        return self._sessionId

    @sessionId.setter
    def sessionId(self, value):
        try:
            self._sessionId = int(value)
        except ValueError:
            self._sessionId = None
        except TypeError:
            self._sessionId = None

    @property
    def wow64(self):
        return self._wow64

    @wow64.setter
    def wow64(self, value):
        try:
            self._wow64 = bool(value)
        except ValueError:
            self._wow64 = None
        except TypeError:
            self._wow64 = None

    @property
    def createTime(self):
        return self._createTime

    @createTime.setter
    def createTime(self, value):
        try:
            self._createTime = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
        except ValueError as e:
            print(e)
            self._createTime = None
        except TypeError:
            self._createTime = None

    @property
    def exitTime(self):
        return self._exitTime

    @exitTime.setter
    def exitTime(self, value):
        try:
            self._exitTime = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
        except ValueError as e:
            print(e)
            self._exitTime = None
        except TypeError:
            self._exitTime = None

    def nbrThreads(self):
        return len(self.threads)

    def nbrHandles(self):
        return len(self.handles)

    def toDict(self) -> dict:
        data = super().toDict()
        data.update({"group": self.__class__.__name__, "pid": self.pid, "ppid": self.ppid, "sessionId": self.sessionId,
                     "wow64": self.wow64, "exitTime": str(self.exitTime), "createTime": str(self.createTime)})
        return data

    def __str__(self) -> str:
        return f"Name: {self.name} || PID: {self.pid}"


if __name__ == "__main__":
    p = Process(name='nom', pid=12345)
    print(p)
    print(p.toDict())
