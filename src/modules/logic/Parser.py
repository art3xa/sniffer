import struct
import collections


class ParsedPacket:
    def __init__(self, raw_packet):
        self.length = len(raw_packet)
        self.is_ip = False
        self.is_tcp = False
        self.is_udp = False
        self.is_icmp = False

        self.eth_data = ProtoParser.parse_eth(raw_packet)
        self.inner_data = self.eth_data.data
        if self.eth_data.proto == 2048:
            self.is_ip = True
            self.ip_data = ProtoParser.parse_ip4(self.inner_data)
            self.inner_data = self.ip_data.data
            if self.ip_data.proto == 1:
                self.is_icmp = True
                self.icmp_data = ProtoParser.parse_icmp(self.inner_data)
                self.inner_data = self.icmp_data.data
            if self.ip_data.proto == 6:
                self.is_tcp = True
                self.tcp_data = ProtoParser.parse_tcp(self.inner_data)
                self.inner_data = self.tcp_data.data
            if self.ip_data.proto == 17:
                self.is_udp = True
                self.udp_data = ProtoParser.parse_udp(self.inner_data)
                self.inner_data = self.udp_data.data


class ProtoParser:
    IP_DATA = collections.namedtuple(
        'IP_DATA', ['version_length', 'type_of_serv', 'packet_length',
                    'packet_id', 'flags_offset', 'ttl', 'next_proto',
                    'checksum', 'source_ip', 'dest_ip'])
    TCP_DATA = collections.namedtuple(
        'TCP_DATA', ['source_port', 'dest_port', 'seq', 'ack', 'length_flags',
                     'window_size', 'checksum', 'urgent_pointer'])
    UDP_DATA = collections.namedtuple(
        'UDP_DATA', ['source_port', 'dest_port', 'lenght', 'checksum'])

    @staticmethod
    def parse_eth(data):
        dest_mac = struct.unpack('BBBBBB', data[0:6])
        source_mac = struct.unpack('BBBBBB', data[6:12])
        next_proto = struct.unpack('>H', data[12:14])[0]
        next_level_data = data[14:]
        return EthData(dest_mac, source_mac, next_proto, next_level_data)

    @staticmethod
    def parse_ip4(data):
        header = ProtoParser.IP_DATA(*struct.unpack('>BBHHHBBHII', data[0:20]))
        version = (header.version_length >> 4) & 0xf
        header_length = header.version_length & 0xf
        flags = (header.flags_offset >> 13) & 0b111
        ofset = header.flags_offset & 0b0001111111111111
        parameters = data[20:header_length*4]
        next_level_data = data[header_length*4:]
        return IpData(version, header_length, header.type_of_serv,
                      header.packet_length, header.packet_id, flags, ofset,
                      header.ttl, header.next_proto, header.checksum,
                      ProtoParser.get_ip_from_int(header.dest_ip),
                      ProtoParser.get_ip_from_int(header.source_ip),
                      parameters, next_level_data)

    @staticmethod
    def parse_tcp(data):
        header = ProtoParser.TCP_DATA(*struct.unpack('>HHIIHHHH', data[0:20]))
        header_length = (header.length_flags >> 12) & 0xf
        flags = header.length_flags & 0b111111
        options = data[20:header_length*4]
        inner_data = data[header_length*4:]
        return TCPData(
            header.source_port, header.dest_port, header.seq, header.ack,
            header_length, flags, header.window_size, header.checksum,
            header.urgent_pointer, options, inner_data)

    @staticmethod
    def parse_udp(data):
        header = ProtoParser.UDP_DATA(*struct.unpack('>HHHH', data[0:8]))
        inner_data = data[8:]
        return UDPData(*header, data=inner_data)

    @staticmethod
    def parse_icmp(data):
        return ICMPData(*struct.unpack('>BBH', data[0:4]), data=data[4:])

    @staticmethod
    def get_ip_from_int(num):
        ip3 = num & 0xff
        ip2 = (num >> 8) & 0xff
        ip1 = (num >> 16) & 0xff
        ip0 = (num >> 24) & 0xff
        return '.'.join(map(str, (ip0, ip1, ip2, ip3)))


class TCPData:
    def __init__(self, source_port, dest_port, seq, ack,
                 header_length, flags, window_size, checksum,
                 urgent_pointer, options, data):
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq = seq
        self.ack = ack
        self.header_length = header_length
        self.flags = flags
        self.window_size = window_size
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer
        if options:
            self.options = options
        else:
            self.options = None
        self.data = data


class UDPData(collections.namedtuple(
     'UDPData', ['source_port', 'dest_port', 'length', 'checksum', 'data'])):
    pass


class ICMPData(collections.namedtuple(
     'ICMPData', ['type', 'code', 'checksum', 'data'])):
    pass



class EthData:
    def __init__(self, dest_mac, source_mac, proto, next_level_data):
        self.dest_mac = dest_mac
        self.source_mac = source_mac
        self.proto = proto
        self.data = next_level_data


class IpData:
    def __init__(self, version, header_length, service, packet_length,
                 id, flags, ofset, ttl, next_proto, checksum, dest_ip,
                 source_ip, parameters, next_level_data):
        self.version = version
        self.header_length = header_length
        self.service = service
        self.packet_length = packet_length
        self.id = id
        self.flags = flags
        self.ofset = ofset
        self.ttl = ttl
        self.proto = next_proto
        self.checksum = checksum
        self.dest_ip = dest_ip
        self.source_ip = source_ip
        if parameters:
            self.parameters = parameters
        else:
            self.parameters = None
        self.data = next_level_data
