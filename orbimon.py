#!/usr/bin/python3

import telnetlib
import sys, traceback, logging
import time, schedule, re
from prometheus_client import Counter, start_http_server, Gauge
from prometheus_client.core import GaugeMetricFamily, REGISTRY

# ### Variables.

HOST = "192.168.1.1"
user = "admin"
password = "password"

# prometheus listener port
prom_port = 8001

#which interfaces to monitor
orbi_interfaces = ['br0','brwan','ath0','ath01','ath1','ath2']

# telnet nonsense handlers
tn = None
tn_err_count = 0

# ### 

def check_connected(tn_o):
    try:
        if tn_o.sock: 
            tn_o.sock.send(telnetlib.IAC+telnetlib.NOP) 
            return True
    except:
        #logging.debug(traceback.print_exc(file=sys.stdout))
        return False

def connect_telnet():
    tn = telnetlib.Telnet(HOST)
    tn.read_until(b"login: ",2)
    tn.write(user.encode('ascii') + b"\n")
    
    if password:
        tn.read_until(b"Password: ",2)
        tn.write(password.encode('ascii') + b"\n")

    print(tn.read_until(b"#",2))
    print(tn.read_eager().decode('ascii'))
    
    return tn    

def check_telnet():
    global tn
    if not check_connected(tn): tn = connect_telnet()


def orbi_interface_metrics(interfaces=None,throughput=None,throughput_history=None):
    global tn

    #eth1 wired 1
    #ath0 2G 0
    #ath01 satellite 0
    #ath1 5G 0
    #ath2 satellite 0
    #ath02 2G-GUEST 0
    #ath11 5G-GUEST 0
    #eth0 wired
    
    metrics = ['rx_bytes','tx_bytes','rx_packets','tx_packets']
    data = {}

    for i in interfaces:
        data[i] = {}
        for m in metrics:
            #tn.write("\r\n".encode())
            tn.write(" cat /sys/devices/virtual/net/{}/statistics/{}\n".format(i,m).encode())
            null = tn.read_until(b"\r\n",5)
            resp = tn.read_until(b"\r\n",5)
            data[i][m] = resp.strip()
            #print(data[i][m])
            time.sleep(.05)
            interface_data = {'interface':i,'traffic_type': m,}
            
            #print(interface_data,i,m)
            #print(int(data[i][m]))
            
            throughput.labels(**interface_data).set(int(data[i][m]))
            throughput_history.labels(**interface_data).inc(int(data[i][m]))


def iptables():
    
    # grab all attached devices
    tn.write("cat /tmp/netscan/all_attach_device\n".encode())
    tn.read_until(b"\r\n",5) #discard
    y = tn.read_until(b"#",5) # output
    d2 = y.decode('ascii').split('\r\n')

    connected_devices = []
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    for i in d2:
        x = pattern.search(i)
        if x: connected_devices.append(x.group())
    
    # grab iptables. check rules exist. then loop to see if devices are defined.
    tn.write("iptables -S\n".encode())
    tn.read_until(b"\r\n",5) #discard
    y = tn.read_until(b"#",5).decode('ascii') # output
    iptables_rules = []
    for yy in y.split('\r\n'):
        iptables_rules.append(yy)

    #print(iptables_rules)
    # -S displays rules oddly. not 1:1 that are submitted. -A/-I
    
    base_rules_to_check = [
            ['-N TRAFFIC_ACCT_WAN_IN','-N TRAFFIC_ACCT_WAN_IN'],
            ['-N TRAFFIC_ACCT_WAN_OUT','-N TRAFFIC_ACCT_WAN_OUT'],
            ['-A FORWARD -i brwan -j TRAFFIC_ACCT_WAN_IN','-I FORWARD -i brwan -j TRAFFIC_ACCT_WAN_IN'],
            ['-A FORWARD -o brwan -j TRAFFIC_ACCT_WAN_OUT','-I FORWARD -o brwan -j TRAFFIC_ACCT_WAN_OUT']
            ]
    ip_rules_to_check = [
            '-A TRAFFIC_ACCT_WAN_IN -d {}/32',
            '-A TRAFFIC_ACCT_WAN_OUT -s {}/32'
            ]
    
    for brtc in base_rules_to_check:
        rule_ok = False
    
        for ir in iptables_rules:
            if ir == brtc[0]: rule_ok=True

        if rule_ok:
            pass #print("rule exists.",brtc)
        else:
            print("rule not found.",brtc)
            tn.write('iptables {}\n'.format(brtc[1]).encode())
            time.sleep(.05)

    for cd in connected_devices:
        for irtc in ip_rules_to_check:
            rule_ok = False

            check_ip_rule = irtc.format(cd)
            
            for ir in iptables_rules:
                if check_ip_rule == ir: rule_ok=True

            if rule_ok:
                pass #print("rule exists.",check_ip_rule)
            else:
                print("rule not found. adding",check_ip_rule)
                tn.write('iptables {}\n'.format(check_ip_rule).encode())
                time.sleep(.05)


def orbi_client_device_metrics():

    tn.write("iptables -L TRAFFIC_ACCT_WAN_IN -n -v -x\n".encode())
    tn.read_until(b"\r\n",5).decode('ascii') #discard
    traffic_in = tn.read_until(b":/#",5).decode('ascii') #discard
    
    for traffic in traffic_in.split('\r\n')[2:-1]:
        #['pkts', 'bytes', 'target', 'prot', 'opt', 'in', 'out', 'source', 'destination']
        traffic_in_data = traffic.split()
        traffic_data = {'src':None,'traffic_type':'rx_bytes','dst':traffic_in_data[7]}
        orbi_client_metrics.labels(**traffic_data).set(int(traffic_in_data[1]))
        
        traffic_data = {'src':None,'traffic_type':'rx_packets','dst':traffic_in_data[7]}
        orbi_client_metrics.labels(**traffic_data).set(int(traffic_in_data[0]))

    tn.write("iptables -L TRAFFIC_ACCT_WAN_OUT -n -v -x\n".encode())
    tn.read_until(b"\r\n",5).decode('ascii') #discard
    traffic_out = tn.read_until(b":/#",5).decode('ascii') #discard
   
    for traffic in traffic_out.split('\r\n')[2:-1]:
        #['pkts', 'bytes', 'target', 'prot', 'opt', 'in', 'out', 'source', 'destination']
        traffic_out_data = traffic.split()
        #print(traffic.split())
        traffic_data = {'dst':None,'traffic_type':'tx_bytes','src':traffic_out_data[6]}
        orbi_client_metrics.labels(**traffic_data).set(int(traffic_out_data[1]))

        traffic_data = {'dst':None,'traffic_type':'tx_packets','src':traffic_out_data[6]}
        orbi_client_metrics.labels(**traffic_data).set(int(traffic_out_data[0]))


######

check_telnet()

# prometheus objects

throughput = Gauge(f'orbi_interface_metrics', 'Packets/Bytes transferred', ['interface','traffic_type'])
throughput_history: throughput_history = Counter(f'orbi_metric_bytes', 'Sum of Packets/Bytes transferred', ['interface','traffic_type'])
orbi_client_metrics = Gauge(f'orbi_client_metrics', 'Packets transferred out', ['src','dst','traffic_type'])

#

start_http_server(prom_port)

orbi_client_device_metrics()
schedule.every(30).seconds.do(check_telnet)
schedule.every(5).seconds.do(
                            orbi_interface_metrics,
                            interfaces=orbi_interfaces,
                            throughput=throughput,
                            throughput_history=throughput_history
                            )
schedule.every(30).seconds.do(iptables)
schedule.every(5).seconds.do(orbi_client_device_metrics)


######

while True:
    try:

        schedule.run_pending()

    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except:
        logging.debug(traceback.print_exc(file=sys.stdout))
        time.sleep(1)
        
        tn_err_count+=1
        if tn_err_count>10:
            tn.close() # get_socket().shutdown(socket.SHUT_WR)
            print("kill socket...")
            tn_err_count = 0
             
        print("check telnet..")
        check_telnet()
        
        pass

    time.sleep(1)

