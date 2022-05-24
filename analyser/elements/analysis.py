import json

from analyser.elements.connection import Connection
from analyser.elements.command import Command
from analyser.elements.dump import Dump
from analyser.elements.node import Node
from analyser.elements.process import Process


class Analysis(Node):
    def __init__(self, name) -> None:
        super().__init__(name)

    def loadDump(self, dumpData: dict):
        # Create the Dump and add it to the Analysis
        dump = Dump(md5=dumpData['hash']['md5'],
                    sha1=dumpData['hash']['sha1'], sha256=dumpData['hash']['sha256'])
        self.children.append(dump)

        # Create the processes and add them to the dump (psscan)
        processes = [Process(name=elt['ImageFileName'],
                             pid=elt['PID'], ppid=elt['PPID'], sessionId=elt['SessionId'], wow64=elt['Wow64'], createTime=elt['CreateTime'], exitTime=elt['ExitTime']) for elt in dumpData['psscan']]

        if 'process_antivirus' in dumpData:
            for proc in processes:
                for scan in dumpData['process_antivirus']:
                    if scan['PID'] == proc.pid:
                        proc.is_malicious = scan['is_malicious']
                        proc.threat = scan['threat']
                        break
        dump.children.extend(processes)

        # Create Commands and add them to the processes (cmdline)
        procs = dump.processes()
        for elt in dumpData['cmdline']:
            for proc in procs:
                if proc.pid == int(elt['PID']) and proc.name == str(elt['Process']):
                    proc.children.append(
                        Command(name=elt['Args'].split()[0], args=elt['Args']))
                    break

        # Create Connections and add them to the processes (netstat)
        for elt in dumpData['netstat'][:-2]:
            for proc in procs:
                if elt['PID'] == None:
                    dump.children.append(Connection(name=elt['Owner'], foreign_addr=elt['ForeignAddr'], foreign_port=elt['ForeignPort'], local_addr=elt['LocalAddr'],
                                                    local_port=elt['LocalPort'], offset=elt['Offset'], owner=elt['Owner'], pid=elt['PID'], protocol=elt['Proto'], state=elt['State']))
                    break
                elif proc.pid == int(elt['PID']):
                    proc.children.append(Connection(name=elt['Owner'], foreign_addr=elt['ForeignAddr'], foreign_port=elt['ForeignPort'], local_addr=elt['LocalAddr'],
                                                    local_port=elt['LocalPort'], offset=elt['Offset'], owner=elt['Owner'], pid=elt['PID'], protocol=elt['Proto'], state=elt['State']))
                    break

    def toDict(self) -> dict:
        data = super().toDict()
        data.update({"group": self.__class__.__name__})
        return data


if __name__ == "__main__":
    with open('Cases/Results/'+'12'+'.json') as f:
        investData = json.load(f)
    a = Analysis("Analyse")
    a.loadDump(investData)
    print(a.toChart())
