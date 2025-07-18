import socket
import time
import sys
import traceback
import manualparamiko

from messages import MSG_MAPPING



class Processor(object):
    ssh_sock = None
    transport = None

    def __init__(self, learnlib, ssh):
        #Mapper
        self.learnlib_host = learnlib[0]
        self.learnlib_port = learnlib[1]

        #Adapter
        self.ssh_host = ssh[0]
        self.ssh_port = ssh[1]
        self.ssh_username = ssh[2]
        self.ssh_passwd = ssh[3]

        #Timing params (for openSSH)
        #self.auth_ok_to = 3.0
        #self.auth_ok_to_total = 3.3
        #self.auth_nok_to = 0.8
        #self.auth_nok_to_total = 1.0
        #self.cmd_to = 0.25
        #self.global_to = 0.9
        #self.global_to_total = 1.0
        #self.buffer_after_newkey = False

        #Timing params (for BitVise)
        self.auth_ok_to = 3.0
        self.auth_ok_to_total = 3.3
        self.auth_nok_to = 3.5
        self.auth_nok_to_total = 4.0
        self.global_to = 0.2
        self.global_to_total = 0.25
        self.cmd_to = 0.2
        self.buffer_after_newkey = True

    def init_ssh_connection(self):
        """ Create an ssh socket and transport layer object """
    
        #Adapter
        try:
            self.ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ssh_sock.connect((self.ssh_host, self.ssh_port))
        except Exception as e:
            print('*** SSH Init Connect failed: ' + str(e))
            traceback.print_exc()
            sys.exit(1)

        #Adapter
        self.transport = manualparamiko.Transport(self.ssh_sock, auth_ok_to=self.auth_ok_to, auth_ok_to_total=self.auth_ok_to_total, auth_nok_to=self.auth_nok_to, auth_nok_to_total = self.auth_nok_to_total, global_to=self.global_to, global_to_total=self.global_to_total, buffer_after_newkey = self.buffer_after_newkey, username=self.ssh_username, passwd=self.ssh_passwd)
        self.transport.active = True

        #Adapter (not sure yet, don't know what packetizer in transport does)
        try:
            banner = self.transport.fuzz_ssh_version()
        except Exception:
            # This is an Powershell hack: timing variances might make Powershell think
            # that a connection is still open. The trail version supports only one simulatious
            # connection. Therefore, wait five seconds and try again. Repeat this process till
            # infinity.
            print('EXCEPTION. Waiting for old connection to die.')
#time
            time.sleep(5)
            return self.init_ssh_connection()
        print('SSH-version: %s' % banner)

    def close_ssh_connection(self):
        """ Close the ssh connection """
        #Adapter
        self.ssh_sock.close()

    def process_reset(self):
        """ Process a Learnlib reset signal """
        #Adapter
        print('RESET SUT')

        if self.ssh_sock:
            self.close_ssh_connection()

        self.init_ssh_connection()

    def process_learlib_query(self, query):
        """ Processes a query identified by a keyword (e.g. DISCONNECT) """

        # Handle reset queries
        #Mapper (process_reset is more adapter-like, however, processing other queries like they originate from the learner means that this should be a task for the mapper)
        if query == 'reset':
            self.process_reset()
            # This is the part were you might want to extend the reset query
            # with certain messages. To enter the SSH authentication phase, for example,
            # execute:
            # self.process_learlib_query("KEXINIT")
            # self.process_learlib_query("KEX30")
            # self.process_learlib_query("NEWKEYS")
            # self.process_learlib_query("SERVICE_REQUEST_AUTH")
            # self.process_learlib_query("UA_PK_OK")

            return 'resetok'

        # Handle empty queries
        #Mapper
        if query == '':
            return ''

        # Handle other queries
        #Not sure, think Mapper
        if query in MSG_MAPPING:
            try:
                return getattr(self.transport, MSG_MAPPING[query])()
            except Exception as e:
                print('An exception has occured: %s' % e)
                traceback.print_exc()
                sys.exit(1)

        raise Exception('Query "%s" is not recognized as an learnlib or reset query' % query)

    def listen(self):
        """ Loop that accepts new connections and receives input """

        # Create a socket and listen for learnlib connections
        #Mapper
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.learnlib_host, self.learnlib_port))
        # sock.settimeout(100)
        sock.listen(10)
        # Listen to a connection (blocking call)
        #Mapper
        print('Waiting for client to connect')

        # Wait for the client to connect (note: most socket commands are blocking)
        while True:
            #Mapper
            conn, addr = sock.accept()

            #Adapter
            print('Connected with ' + addr[0] + ':' + str(addr[1]))
            self.init_ssh_connection()

            while True:
                try:
                    # This will handle either multirun queries (e.g. "IGNORE DISCONNECT IGNORE") or
                    # single run queries (e.g. just "DISCONNECT"). If the first argument is an integer,
                    # the query will be repeated int times (this is useful for nondeterminism test
                    # cases).

                    #Mapper
                    commands = conn.recv(4096).rstrip().split()
                    # print commands
                    # commands = commands.rstrip(".").split()

                    # Repeat multiple times?
                    #Mapper
                    try:
                        repeat = int(commands[0])
                        del commands[0]
                    except IndexError:
                        # An empty string has been sent
                        commands = ['']
                        repeat = 1
                    except ValueError:
                        # No repeater has been sent, we are doing one run
                        repeat = 1

                    #Mapper
                    if len(commands) > 1 and 'reset' not in commands:
                        raise Exception('You are doing a multiquery but you are not resetting your sut')

                    # Execute single OR multiquery 'repeat'-many times
                    #Mapper
                    for i in xrange(repeat):
                        result = ''
                        for ci, command in enumerate(commands):
                            print('[%s]' % self.transport)
                            print('Sending %s...' % command)
                            response = self.process_learlib_query(command)

                            result += response
                            # If this is not the last command, add a space
                            if ci != len(commands)-1:
                                result += ' '

                            # 0.15 effectively prevents ssh nondeterminism on SSH6.6 localhost
#time param
                            time.sleep(self.cmd_to)

                        # Add a newline after a run of one or many commands
                        conn.send('%s\n' % result)
                except socket.error:
                    print traceback.print_exc()
                    print('\nCient disconnected (socket.error)')
                    break
            print('Ready for new connection')

        print('Closing connection')
        sock.close()


# Start listening!
#Unclear, contains both connection to SUT and learner
if len(sys.argv) > 1: 
    sshServerIP = sys.argv[1] 
else:
    sshServerIP = "192.168.0.140"
if len(sys.argv) > 2:
    sshServerPort = int(sys.argv[2])
else:
    sshServerPort = 22
if len(sys.argv) > 3:
    sshUsername = sys.argv[3]
else:
    sshUsername = "root"
if len(sys.argv) > 4:
    sshPasswd = sys.argv[4]
else:
    sshPasswd = "pipilu123456"


sshAdr = (sshServerIP, sshServerPort, sshUsername, sshPasswd)
proc = Processor(learnlib=('127.0.0.1', 8643), ssh=sshAdr)
print "Starting mapper with parameters\n", vars(proc)
proc.listen()