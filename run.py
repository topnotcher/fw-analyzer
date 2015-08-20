def main():
    import sys, asyncio, logging, yaml

    from .syslog import SyslogServer
    from .util.plugin import load_class

    logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger('MAIN')

    loop = asyncio.get_event_loop()

    # start asyslog server on UDP/50514
    server = SyslogServer(bind_port=50514)
    server.start(loop)

    config = {}
    with open('config.yml', 'r') as fh:
        config = yaml.load(fh)

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
