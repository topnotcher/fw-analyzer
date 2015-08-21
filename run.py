import sys
import asyncio
import logging
import yaml
import argparse

from .syslog import SyslogServer
from .util.plugin import load_class

def parse_args():
    """
    Parse command line options and configuration file, returning a single
    merged dictionary in which command line options (if present) override the
    values from the configuration file.
    """
    parser = argparse.ArgumentParser(prog='fwaudit',
                                     description='Run fwaudit')

    parser.add_argument('--port', '-p', metavar='PORT', type=int, nargs='?',
                        help='UDP syslog port', dest='bind_port', default=8750)

    parser.add_argument('--config', '-c', metavar='FILE', type=str, nargs='?', required=True,
                        help='Path to configuration file')

    parser.add_argument('--daemon', '-d', type=bool, nargs='?',
                        help='Whether or not to daemonize', dest='daemonize')

    parser.add_argument('--log-level', '-l', metavar='LEVEL', type=str, nargs='?',
                        help='Logging level name (see logging module)', dest='log_level')

    parser.add_argument('--log-file', '-f', metavar='FILE', type=str, nargs='?',
                        help='Path to logfile', dest='log_file')

    args = {
        'daemonize': False,
        'log_level': 'WARN',
        # log_file ?
        'syslog': {
            'bind_addr': '0.0.0.0',
            'bind_port' : 50514,
        },
    }

    cmd_args = parser.parse_args()

    # config file overrides defaults
    with open(cmd_args.config, 'r') as fh:
        args.update(yaml.load(fh))

    #
    # Command-line arguments override config file
    #
    if cmd_args.bind_port:
        args['syslog']['bind_port'] = cmd_args.bind_port

    # LoL this isn't even implemented
    if cmd_args.daemonize:
        args['daemonize'] = cmd_args.daemonize

    if cmd_args.log_level:
        args['log_level'] = cmd_args.log_level

    if cmd_args.log_file:
        args['log_file'] = cmd_args.log_file

    return args

def get_logging_level(level_name):
    """
    Given a logging level name (e.g. DEBUG), return the logging level number
    (e.g. logging.DEBUG)
    """
    level_name = level_name.upper()

    if not hasattr(logging, level_name):
        raise ValueError('Invalid logging level: %s' % level_name)
    elif not isinstance(getattr(logging, level_name), type(logging.WARN)):
        raise ValueError('Invalid logging level: %s' % level_name)
    else:
        return getattr(logging, level_name)

def init_logger(args):
    """
    Initialize loggers: stdout or file + stdout.
    """
    log_level = get_logging_level(args['log_level'])

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')

    sh = logging.StreamHandler()
    sh.setFormatter(formatter)

    if 'log_file' in args:
        filename = args['log_file']
        fh = logging.FileHandler(filename)
        fh.setLevel(log_level)
        fh.setFormatter(formatter)

        logger.addHandler(fh)

        # If logging to a file, still log CRITICAL to stdout
        sh.setLevel(logging.CRITICAL)
    else:
        sh.setLevel(log_level)

    logger.addHandler(sh)

def main():
    config = parse_args()

    init_logger(config)
    log = logging.getLogger('MAIN')

    loop = asyncio.get_event_loop()

    # start asyslog server on UDP/50514
    server = SyslogServer(**config['syslog'])
    server.start(loop)

    for fw_name in config['fws']:
        fw = config['fws'][fw_name]
        class_name, cls = load_class(fw['class'])

        if cls is None:
            log.error("Failed to load %s", class_name)
        else:
            manager = cls(loop, **fw['args'])
            server.register_listener(manager)

    loop.run_forever()

if __name__ == '__main__':
    main()
