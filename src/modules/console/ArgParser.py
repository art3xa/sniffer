from argparse import ArgumentParser, FileType


class ArgParser:
    """ Argument Parser"""

    def __init__(self, args):
        self._parser = ArgumentParser(prog="Sniffer",
                                      description="Sniffer for "
                                                  "Linux (pcap format)",
                                      )
        self._args = args
        self._add_arguments()

    def _add_arguments(self):
        """
        Add arguments to the parser
        """
        self._parser.add_argument('-i', '--interface',
                                  help='Use this network '
                                       'interface to capture packets')
        self._parser.add_argument('-f', '--file', type=FileType('wb'),
                                  default='sniffer.pcap',
                                  help='File path for saving packets (pcap format), default: sniffer.pcap')

    def parse(self):
        """
        Parsing arguments
        """
        args = self._parser.parse_args(self._args)

        return args
