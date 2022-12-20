import struct


class PcapWriter:
    def __init__(self):
        self.file = None

    def open(self, file):
        self.file = file
        self.file.write(self.create_global_header())

    def close(self):
        if self.file:
            self.file.close()

    @staticmethod
    def create_global_header():
        magic = b'\xd4\xc3\xb2\xa1'
        version1 = b'\x02\x00'
        version2 = b'\x04\x00'
        zone = b'\x00\x00\x00\x00'
        sigfigs = b'\x00\x00\x00\x00'
        snaplen = b'\x00\x00\x04\x00'
        network = b'\x01\x00\x00\x00'
        return magic + version1 + version2 + zone + sigfigs + snaplen + network

    @staticmethod
    def create_pcap_header(packet, time):
        timestamp_seconds, timestamp_microseconds = time
        length = len(packet)
        return struct.pack('<IIII', timestamp_seconds,
                           timestamp_microseconds,
                           length, length)

    def write_packet(self, packet, time):
        if not self.file:
            return
        header = self.create_pcap_header(packet, time)
        self.file.write(header)
        self.file.write(packet)
