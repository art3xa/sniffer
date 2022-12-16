class Visualiser:
    @staticmethod
    def print_packet(packet, time):
        length = packet.length
        if packet.is_ip:
            if packet.is_tcp:
                flags = []
                if packet.tcp_data.flags >> 5 == 1:
                    flags.append('URG')
                if (packet.tcp_data.flags >> 4) & 1 == 1:
                    flags.append('ACK')
                if (packet.tcp_data.flags >> 3) & 1 == 1:
                    flags.append('PSH')
                if (packet.tcp_data.flags >> 2) & 1 == 1:
                    flags.append('RST')
                if (packet.tcp_data.flags >> 1) & 1 == 1:
                    flags.append('SYN')
                if packet.tcp_data.flags & 1 == 1:
                    flags.append('FIN')
                flags_str = ', '.join(flags)
                print(f'{time} IP/TCP from {packet.ip_data.source_ip}'
                      f':{packet.tcp_data.source_port} '
                      f' to {packet.ip_data.dest_ip}'
                      f':{packet.tcp_data.dest_port} [{flags_str}] '
                      f'{length} bytes')
                return

            if packet.is_udp:
                print(f'{time} IP/UDP from {packet.ip_data.source_ip}'
                      f':{packet.udp_data.source_port} '
                      f' to {packet.ip_data.dest_ip}'
                      f':{packet.udp_data.dest_port} {length} bytes')
                return

            if packet.is_icmp:
                print(f'{time} IP/ICMP from {packet.ip_data.source_ip} '
                      f'to {packet.ip_data.dest_ip} '
                      f'(type={packet.icmp_data.type}, '
                      f'code={packet.icmp_data.code}) {length} bytes')

            print(f'{time} IP from {packet.ip_data.source_ip} '
                  f'to {packet.ip_data.dest_ip} {length} bytes')
            return
        source_mac = '-'.join(format(num, 'x').rjust(2, '0')
                              for num in packet.eth_data.source_mac)
        dest_mac = '-'.join(format(num, 'x').rjust(2, '0')
                            for num in packet.eth_data.dest_mac)
        print(f'{time} ETH from {source_mac} to {dest_mac} {length} bytes')
