import json
import logging
import subprocess
import time
import sys
import signal
from collections import Counter

from scapy.layers.http import HTTPRequest, HTTPResponse  # import HTTP packet
from scapy.all import *
from scapy.layers.inet import IP, TCP

address = Counter()
connF = Counter()
connS = Counter()
partial_requests = Counter()

time_L3 = 0
time_L4 = 0
time_partial = 0
suspicion = 0

interface = ""
slow_signatures_slice = []
slow_partial_slice = []
slow_volume_slice = []
flood_signatures_slice = []
flood_volume_slice = []
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)


def reset_iptables():
    try:
        subprocess.run(["sudo", "iptables", "-F"], stdout=subprocess.DEVNULL)
        logging.info("Flushed IPtables")

    except subprocess.CalledProcessError:
        logging.error("Error flushing IPtables")


# function for adding DROP rule to IPTables
def block_ip(addr, name):
    check = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-p", "tcp", "-s", addr, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check.returncode == 1:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "-s", addr, "-j", "DROP"])
        logging.warning(f"Blocked suspicious IP {addr} (Suspicion on {name} attack)")

    return check.returncode


# function for loading JSON file
def load_json_file(filename):
    try:
        f = open(filename)
        logging.info(f"Signatures loaded from file {filename}")
        return json.load(f)

    except FileNotFoundError as err:
        logging.error(f"Error with opening file {err.filename}")


def load_json(json_data, value_list):
    if isinstance(json_data, dict):
        for value in json_data.values():
            load_json(value, value_list)
    elif isinstance(json_data, list):
        for item in json_data:
            load_json(item, value_list)
    else:
        value_list.append(json_data)


def load_signatures():
    slow_signatures_list = []
    flood_signatures_list = []

    signatures = load_json_file("signatures.json")
    load_json(signatures['SlowDoS'], slow_signatures_list)
    load_json(signatures['FloodDoS'], flood_signatures_list)

    return slow_signatures_list, flood_signatures_list


def sliced_signatures(slow, flood):
    slow_volume = slow[7:]
    slow_partial = slow[5:7]
    flood_volume = flood[3:]
    slow_signatures = slow[:5]
    flood_signatures = flood[:3]

    return slow_signatures, slow_partial, slow_volume, flood_signatures, flood_volume


# function for measuring time between requests
def measure_time(time_previous):
    if time_previous != 0:
        time_actual = time.time()
        res = (time_actual - time_previous)

    else:
        res = 0
    return res


def get_flag_name(flag):
    flag_name = flag[0]
    return flag_name


def calculate_window_size(content):
    return len(content.encode()) + 2


def tcp_kill(dst):
    proc = subprocess.Popen(["tcpkill", "host", dst], stderr=subprocess.PIPE)
    p = proc.pid
    time.sleep(10)
    os.kill(p,signal.SIGINT)


def sniff_packets(iface=None):
    """
    Sniff packets with parameter iface, if the parameter is None, then the default interface is used
    """
    reset_iptables()
    loaded_sigs = load_signatures()
    slices = sliced_signatures(loaded_sigs[0], loaded_sigs[1])
    global slow_signatures_slice, slow_volume_slice, slow_partial_slice, flood_signatures_slice, flood_volume_slice
    slow_signatures_slice = slices[0]
    slow_partial_slice = slices[1]
    slow_volume_slice = slices[2]
    flood_signatures_slice = slices[3]
    flood_volume_slice = slices[4]

    # if iface is defined use it, else run with default

    if iface:
        logging.info(f"Listening on interface {iface}")
        sniff(prn=process_packet, iface=iface, store=False)
    else:
        logging.info(f"Listening on default interface")
        sniff(prn=process_packet, store=False)


def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """

    global time_L3, time_L4, time_partial, suspicion

    # if packet has TCP layer and is not meant for HTTP port
    if packet.haslayer(TCP) and packet[TCP].sport != 80:
        source = packet[IP].src
        flag = packet[TCP].flags
        protocol = packet[IP].get_field('proto').i2s[packet[IP].proto].upper()
        parameters = (protocol, flag)
        suspicious = source
        if flag == get_flag_name(flood_signatures_slice[2]):
            # connections with SYN flag
            connF[flag] += 1
            # connections with same IP address
            address[suspicious] += 1
            # starts timer for connections per X seconds
            if address[suspicious] == 1 or connF[flag] == 1:
                time_L3 = time.time()
            # if number of connections reaches limit set in "connections"
            if address[suspicious] == flood_volume_slice[0] or connF[flag] == flood_volume_slice[0]:
                # time of reaching the number of connections is calculated
                res = round(measure_time(time_L3))
                #logging.debug(res)
                # if time is smaller than time set in "per-seconds" the connection is blocked
                if res <= flood_volume_slice[1]:
                    block_ip(suspicious, flood_signatures_slice[0])
                    address.clear()

                else:
                    res = 0
                    address.clear()
                    connF.clear()
        if source == suspicious and flag == "A":
            address.clear()
            connF.clear()

    # if this packet is an HTTP Request
    if packet.haslayer(HTTPRequest):

        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        source = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        # build content of request
        path = packet[HTTPRequest].Path.decode()
        http_version = packet[HTTPRequest].Http_Version.decode()
        content = method + " " + path + " " + http_version
        # calculate window size
        window_size = calculate_window_size(content)
        connS[source] += 1

        # time is calculated between requests
        res = measure_time(time_L4)
        logging.debug(res)
        # if number of connections per X seconds is higher than set limit from json, connection will be blocked
        if connS[source] > slow_volume_slice[0] and res <= slow_volume_slice[1]:
            blockedV = block_ip(source, slow_signatures_slice[0])
            if blockedV == 1:
                logging.warning("Blocked due to volume limit")
                tcp_kill(source)
            connS.clear()
        else:
            connS.clear()
        keep_alive = "None" if packet[HTTPRequest].Keep_Alive is None else packet[HTTPRequest].Keep_Alive

        content_length = "None" if packet[HTTPRequest].Content_Length is None else packet[HTTPRequest].Content_Length

        connection = "None" if packet[HTTPRequest].Connection is None else packet[HTTPRequest].Connection.decode()

        parameters = (content, window_size, connection, content_length)
        # cycle used to compare defined signatures and captured packet
        # if the values are equal, suspicion is raised
        for packet_param, signature in zip(parameters,slow_signatures_slice[1:]):
            if packet_param == signature:
                suspicion += 1
                # if suspicion exceeds set limit connection is blocked
                if suspicion >= 4:
                    block_ip(source, slow_signatures_slice[0])
                    logging.warning(f"Blocked due to signature match, suspicion is {suspicion}")
                    tcp_kill(source)
                    suspicion = 0
            else:
                suspicion = 0
        time_L4 = time.time()

    # if there is HTTP content in TCP packet payload and dest. port is 80
    if TCP in packet and "HTTP" in packet[TCP].payload and packet[TCP].dport == 80:
        source = packet[IP].src
        sport = packet[TCP].sport
        partial_requests[sport] += 1

        if packet.haslayer(Raw) and partial_requests[sport] >= 1:
            time_since = measure_time(time_partial)

            # if time exceeds maximum time allowed between requests connection is blocked
            if time_since >= slow_partial_slice[0]:
                blockedT = block_ip(source,slow_signatures_slice[0])
                if blockedT == 1:
                    logging.warning("Blocked due to exceeding maximum time between partial requests")
                    tcp_kill(source)
                partial_requests.clear()
            # if maximum number of partial requests is exceeded connection is blocked
            elif partial_requests[sport] >= slow_partial_slice[1]:
                blockedN = block_ip(source, slow_signatures_slice[0])
                if blockedN == 1:
                    logging.warning("Blocked due to exceeding maximum number of partial requests")
                    tcp_kill(source)
                partial_requests.clear()
            time_partial = time.time()


def signal_handler(signum, frame):
    reset_iptables()
    logging.info("\nUser interruption, shutting Down")
    sys.exit(0)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", help="Specify interface")

    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    signal.signal(signal.SIGINT, signal_handler)
    sniff_packets(iface)




