from src.modules.logic.Parser import ParsedPacket
from src.modules.helpers.Timer import Timer
from src.modules.console.Visualiser import Visualiser


class Program:
    def __init__(self, writer, sock, timer=Timer(),
                 visualiser=Visualiser(), host='0.0.0.0'):
        self.sock = sock
        self.timer = timer
        self.visualiser = visualiser
        self.writer = writer
        self.host = sock.get_host()

    def run(self):
        self.sock.create()
        self.timer.update_timer()
        while True:
            data = self.sock.recv_data()
            time = self.timer.get_time()
            delta = self.timer.get_time_delta()
            self.writer.write_packet(data[0], time)
            parsed = ParsedPacket(data[0])
            self.visualiser.print_packet(parsed, delta)
