import sys
from src.modules.helpers.pcap_writer import PcapWriter
from src.modules.logic.program import Program
from src.modules.helpers.socket_api import SocketAPI
from src.modules.helpers.timer import Timer
from src.modules.console.arg_parser import ArgParser


def main():
    if sys.platform == 'win32':
        sys.stderr.write('Windows don\'t supported\n')
        sys.exit(1)
    parsed = ArgParser(sys.argv[1:]).parse()
    host = SocketAPI.get_host()
    if parsed.interface:
        sock = SocketAPI(parsed.interface)
    else:
        sock = SocketAPI()
    writer = PcapWriter()
    if parsed.file:
        writer.open(parsed.file)
    timer = Timer()
    program = Program(writer, sock, host=host)
    try:
        program.run()
    except KeyboardInterrupt as e:
        pass
    finally:
        writer.close()


if __name__ == '__main__':
    main()
