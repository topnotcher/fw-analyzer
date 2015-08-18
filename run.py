def main():
    import sys, asyncio, logging

    from .syslog import SyslogServer
    from .cisco.client import CiscoSSHClient
    from .cisco.manager import CiscoFwManager

    logging.basicConfig(level=logging.DEBUG)

    loop = asyncio.get_event_loop()
    
    # start asyslog server on UDP/50514
    server = SyslogServer(bind_port=50514)
    server.start(loop)

    # Create a CiscoFwManager
    conn = CiscoSSHClient(sys.argv[1], sys.argv[2], sys.argv[3], loop)
    manager = CiscoFwManager(conn, loop, None)

    # register the CiscoFwManager as syslog receiver
    server.register_listener(manager)

    loop.run_forever()

if __name__ == '__main__':
    main()