import argparse
import socket
import ipaddress
import itertools


def get_network_hosts(ip):
    """Takes an ip address and returns a generator that yields a stream
    of IPv4 addresses within the same subnet.
    
    Args:
        ip (str): The ip address being checked.

    Returns:
        A generator function that yields IPv4 addresses.
    """

    A = ipaddress.IPv4Network('10.0.0.0/8')
    B = ipaddress.IPv4Network('172.16.0.0/16')
    C = ipaddress.IPv4Network('192.168.0.0/24')

    ip_class = None
    if ip in A:
        ip_class = A
    elif ip in B:
        ip_class = B
    elif ip in C:
        ip_class = C
    
    return (str(host) for host in ip_class)


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

    print("Scanning for open ports...")
    for host, port in addresses:
        try:
            # create a new socket for making connections
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # attempt to connect to the host via the given port
            s.connect((host, int(port)))

            # if successful, add the host and port combination
            # and close the socket
            print(f'{host}:{port} OPEN')
            s.close()
        except:
            # if we fail to connect ignore the exception and move on
            continue


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

    args = parser.parse_args()

    # if no ports are specified use the well-known ports
    if not args.ports:
        ports = range(1, 1024)
    else:
        ports = args.ports

    try:
        main(args.ip, ports, args.is_network_wide)
    except (KeyboardInterrupt, SystemExit):
        exit()
