import argparse
import socket
import ipaddress
import itertools
import datetime
import re


def get_network_hosts(ip):
    """Takes an ip address and returns a generator that yields a stream
    of IPv4 addresses within the same subnet.
    
    Args:
        ip (str): The ip address being checked.

    Returns:
        A generator function that yields IPv4 addresses.
    """

    A = ipaddress.IPv4Network('10.0.0.0/8')
    B = ipaddress.IPv4Network('172.16.0.0/12')
    C = ipaddress.IPv4Network('192.168.0.0/16')

    ip_class = None
    if ip in A:
        ip_class = A
    elif ip in B:
        ip_class = B
    elif ip in C:
        ip_class = C
    
    return (str(host) for host in ip_class)


def has_vulnerability(banner):
    """Checks if there are any reported vulnerabilities associated
    with the banner being passed in.
    
    Args:
        banner (str): The name of the application banner.

    Returns:
        A boolean value of True if the banner has a vulnerability or
        False if the banner does not have a vulnerability.
    """

    # create a simple key-value pair containing application banners
    # and whether or not they have vulnerabilites
    # the vulnerability database is currently limited to banners
    # of applications that have been detected by pscan and research has shown
    # some level of vulnerability
    db = [
        'nginx',
        'apache',
        'microsoft-iis',
        'lighttpd',
        'ssh-2.0-dropbear_0.53.1'
    ]
    
    return banner.lower().split('/')[0] in db


def grab_banner(ip, port):
    """Grabs the banner (if any) associated with the address ip:port.
    
    Args:
        ip (str): The machine's IPv4 address.
        port (int): The port number of the machine.

    Returns:
        A string containing the application banner running on the address
        specified by ip:port.
    """
    try:
        # create a new socket for making connections
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(0.5)

        # attempt to connect to the host via the given port
        s.connect((ip, int(port)))

        request = 'GET / HTTP/1.1\r\n\r\n'
        s.send(request.encode('utf-8'))
        response = s.recv(4096).decode('utf-8')

        # retrieve the banner from applications if they respond
        # http is a special case and requires an http request to be 
        # sent to further ascertain the application being run
        if 'HTTP' in response:
            # get the value of the http server response header
            banner = re.search('(Server: .+)|(X-Powered-By: .+)', response)\
                        .group(0).split(': ')[1]
        else:
            banner = response
        
        s.close()

        return banner.strip()
    except:
        # if we fail to connect ignore the exception and move on
        return ''


def main(ip, ports, is_network_wide):
    """Attempts to connect to each port of the machine identified by
    the provided ip address using the specified protocol.
    
    Args:
        ip (str): The IP address of the machine being scanned.
        ports (int[]): A list of ports to be scanned.
        protocol (str): The transport layer protocol to be used.
    """

    if is_network_wide:
        # get a list of hosts within the same class and domain of the
        # specified ip
        hosts = get_network_hosts(ipaddress.IPv4Address(ip))
    else:
        hosts = [ip]

    # create 2-tuples representing hosts and each port to be checked
    addresses = itertools.product(hosts, ports)

    print(f'Starting pscan at {datetime.datetime.now()}\n')

    found = []
    for host, port in addresses:
        banner = grab_banner(host, port)

        if banner:
            is_vulnerable = \
                'VULNERABLE' if has_vulnerability(banner) else 'OK'
            found.append((host, port, banner, is_vulnerable))

    # print('HOST\t\tPORT\tSTATE\tBANNER\t\t\tVULNERABLE')
    for host, port, banner, is_vulnerable in found:
        print(f'{host}\t{port}/tcp\tOPEN\t{banner}\t{is_vulnerable}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='pscan')

    # create required command line arguments to capture the machine
    # to be scanned and a list of ports to check
    parser.add_argument(
        'ip',
        type=str,
        help='the IP address of the machine to be scanned'
    )

    parser.add_argument(
        '--ports',
        '-p',
        dest='ports',
        nargs='+',
        type=int,
        help='the ports to be tested by the scanner'
    )

    parser.add_argument(
        '--network',
        '-n',
        dest='is_network_wide',
        action='store_true',
        help='include to perform a network wide search'
    )

    parser.add_argument(
        '--range',
        '-r',
        dest='range',
        nargs=2,
        type=int,
        help='the upper and lower range of ports to be scanned'
    )

    args = parser.parse_args()

    # if no ports are specified use the well-known ports
    if not args.ports:
        if not args.range:
            ports = range(1, 1024)
        else:
            ports = range(args.range[0], args.range[1])
    else:
        ports = args.ports

    try:
        main(args.ip, ports, args.is_network_wide)
    except (KeyboardInterrupt, SystemExit):
        exit()
