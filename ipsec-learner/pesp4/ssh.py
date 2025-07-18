import paramiko

def execute_ssh_commands(hostname, port, username, password, commands):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(hostname=hostname, port=port, username=username, password=password)

        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            _ = stdout.read()

    except paramiko.AuthenticationException:
        print("Authentication failed. Please check the user name and password.")
    except paramiko.SSHException as e:
        print(f"SSH connection error: {str(e)}")
    finally:
        client.close()


def reset_strongswan():
    hostname = "192.168.11.4"
    port = 22  
    username = "root"
    password = "zdl"
    commands = ['/home/zdl/strongswan/IPSEC/sbin/ipsec stop', 'sleep 0.3',
                '/home/zdl/strongswan/IPSEC/sbin/ipsec start', 'sleep 0.3',
                '/home/zdl/strongswan/IPSEC/sbin/swanctl -q', 'sleep 0.3']
    execute_ssh_commands(hostname, port, username, password, commands)

def reset_libreswan():
    hostname = "192.168.100.201"
    port = 22  
    username = "root"
    password = "ju"
    commands = ['ipsec restart', 'sleep 1']  
    execute_ssh_commands(hostname, port, username, password, commands)


# reset_strongswan()