import paramiko, base64
import select
import re

class CiscoClient(object):
    def __init__(self, host, user, passwd):
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(host, username=user, password=passwd, look_for_keys=False, allow_agent=False)
        self._linesep = b'\r\n'

        self._conn = self._client.invoke_shell()
        self.collect_until_prompt(b'^.+# ')

    def get_last_line(self, buf):
        pos = buf.rfind(self._linesep)
        if pos == -1:
            return buf
        else:
            return buf[pos + len(self._linesep):]

    def collect_until_prompt(self, prompt, interchar_timeout=5.0, ignore_echo=0):
        buf = b''
        select_timeout = 0.1
        timeout_counter = 0.0

        while True:
            rlist, wlist, xlist = select.select([self._conn], [], [], select_timeout)

            if not rlist:
                timeout_counter += select_timeout
                last_line = self.get_last_line(buf)
                result = re.match(prompt, last_line)

                if result:
                    drop_len = len(self._linesep) + len(last_line)
                    return buf[ignore_echo : -1 * drop_len]
                elif timeout_counter >= interchar_timeout:
                    return None
            else:
                timeout_counter = 0.0
                buf += self._conn.recv(1024)

        return None

    def exec_cmd(self, cmd):
        if not isinstance(cmd, bytes):
            send_cmd = cmd.encode('ascii')
        else:
            send_cmd = cmd

        send_cmd += self._linesep

        self._conn.sendall(send_cmd)

        prompt = b'^.+# '
        result = self.collect_until_prompt(prompt, ignore_echo=len(send_cmd))

        if not result:
            return None
        else:
            return result

if __name__ == '__main__':
    import sys
    client = CiscoClient(sys.argv[1], sys.argv[2], sys.argv[3])

    result = client.exec_cmd('show ver')
    print(result.decode('ascii'))

    result = client.exec_cmd('show access-list')
    print(result.decode('ascii'))
