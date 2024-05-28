from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp

from ryu.lib import hub
import csv
import time
import math 
import statistics 
from datetime import datetime


#-------------------------------------------------------#
APP_TYPE = 0
#0 datacollection

#TEST_TYPE is applicable only for datacollection
#0  ping, 1 telnet, 2-VoIP 3-DNS

TEST_TYPE = 3


#data collection interval
INTERVAL = 10
#-------------------------------------------------------#

#------------------------------
keystore = {}

def calculate_value(key, val):
    '''
    store the val in kv. and calcualte the rate per sec
    '''
    if key in keystore:
        oldval = keystore[key]
        cval = (val - oldval) 
        # storing the val
        keystore[key] = val
        return cval
    else:
        keystore[key] = val
        return None



#---------------------------------------------------
def init_csv():
    fname = "result.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    header = ["fwd_byte_count", "fwd_packet_count","fwd_bytes_rate","fwd_packet_rate", "fwd_avg_packet_rate", "fwd_avg_bytes_rate",
              "rev_byte_count", "rev_packet_count","rev_bytes_rate","rev_packet_rate", "rev_avg_packet_rate", "rev_avg_bytes_rate",
              "type"]
    writ.writerow(header)


def write_csv(fwddata, revdata):
    fname = "result.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    row = [ fwddata["byte_count"],
            fwddata["packet_count"],
            fwddata["bytes_rate"],
            fwddata["packet_rate"],
            fwddata["avg_packet_rate"],
            fwddata["avg_bytes_rate"],
            revdata["byte_count"],
            revdata["packet_count"],
            revdata["bytes_rate"],
            revdata["packet_rate"],
            revdata["avg_packet_rate"],
            revdata["avg_bytes_rate"]
           ]
    row.append(str(TEST_TYPE))
    writ.writerow(row)
#---------------------------------------------------



class TrafficClassifierML(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficClassifierML, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_thread = hub.spawn(self._flow_monitor)
        self.datapaths = {}
        self.mitigation = 0
        self.mlobj = None
        self.arp_ip_to_port = {}
        self.flowdb = {}
        if APP_TYPE == 0:
            self.logger.info("Application Started with Data Collection Mode")
            init_csv()



    def _flow_monitor(self):
        #inital delay
        hub.sleep(INTERVAL*2)
        while True:
            #self.logger.info("Starts Flow monitoring")
            #print(self.flowdb)
            self.flowdb = {}
            for dp in self.datapaths.values():
                self.request_flow_metrics(dp)
            hub.sleep(INTERVAL)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        #flow_serial_no = get_flow_number(datapath.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def request_flow_metrics(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)


    def calculate_flow_stats(self, flow_unique_id, duration, byte_count, 
                             packet_count, reverse_flow_unique_id,
                             srcip,dstip,proto,srcport,dstport):        
        bhdr = flow_unique_id + "_byte_count"
        phdr = flow_unique_id + "_packet_count"
        change_in_bytes = calculate_value( bhdr , int(byte_count))
        change_in_packets = calculate_value( phdr , int(packet_count))
        #print(change_in_packets, change_in_bytes)
    
        if change_in_bytes == None and change_in_packets == None:
            return

        avg_packet_rate = round(packet_count/  duration , 1)
        avg_bytes_rate = round( byte_count/duration, 1)

        packet_rate = round( change_in_packets / INTERVAL, 1)
        bytes_rate = round(change_in_bytes /INTERVAL, 1)
        #packet_count, byte_count, packet_rate, bytes_rate, 

        #print(flow_unique_id, "byte_count", byte_count, "packet_count",packet_count,
        #      "bytes_rate", bytes_rate, "packet_rate",packet_rate,
        #      "avg_packet_rate",avg_packet_rate, "avg_bytes_rate",avg_bytes_rate)

        self.flowdb[flow_unique_id] = {"byte_count": byte_count,
                                       "packet_count":packet_count,
                                       "bytes_rate": bytes_rate,
                                       "packet_rate":packet_rate,
                                       "avg_packet_rate":avg_packet_rate,
                                       "avg_bytes_rate":avg_bytes_rate,
                                       "reverse_flow_unique_id": reverse_flow_unique_id,
                                       "src_ip": srcip,
                                       "dst_ip": dstip,
                                       "protocol": proto,
                                       "src_port": srcport,
                                       "dst_port": dstport
                                       }
                                    

    @set_ev_cls([ofp_event.EventOFPFlowStatsReply], MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        t_flows = ev.msg.body
        flags = ev.msg.flags
        dpid = ev.msg.datapath.id

        for flow in t_flows:
            #print(flow)
            m = {}
            srcip = None
            dstip = None
            proto = 0
            srcport = 0
            dstport = 0

            for i in flow.match.items():
                key = list(i)[0]  # match key 
                val = list(i)[1]  # match value 
                if key == "ipv4_src":
                    srcip = val
                    #print key,val
                if key == "ipv4_dst":
                    dstip = val
                if key == "ip_proto":
                    proto = val
                if key == "tcp_src":
                    srcport = val
                if key == "tcp_dst":
                    dstport = val                                      

            if srcip == None and dstip == None:
                continue
            '''
            flow.byte_count
            flow.duration
            flow.packet_count
            '''
            flow_unique_id = str(dpid) + "_" + str(srcip) +"_" +str(dstip) + "_"+ str(proto) +"_" +str(srcport) + "_" + str(dstport)
            reverse_flow_unique_id = str(dpid) + "_" + str(dstip) +"_" +str(srcip) + "_"+ str(proto) +"_" +str(dstport) + "_" + str(srcport)
            #print(flow_unique_id)
            self.calculate_flow_stats(flow_unique_id, flow.duration_sec, flow.byte_count, flow.packet_count, reverse_flow_unique_id,
                                      srcip, dstip, proto, srcport , dstport )

        print("All flows are processed, lets evaluate it")
        processed_flowids = []

        for key in self.flowdb:
            #print(key, self.flowdb[key])
            revflowid = self.flowdb[key]['reverse_flow_unique_id']

            if key in processed_flowids and revflowid in processed_flowids:
                continue

            if revflowid in self.flowdb:
                #print("fwdflowid", key, "value", self.flowdb[key])
                #print("revflowid", revflowid, "value", self.flowdb[revflowid])

                processed_flowids.append(key)
                processed_flowids.append(revflowid)

                if APP_TYPE==0:
                    #writecsv
                    write_csv(self.flowdb[key], self.flowdb[revflowid])

                else:
                    #ML detection mechanism
                    self.run_classifier(self.flowdb[key], self.flowdb[revflowid])
            else:

                processed_flowids.append(key)

                revdata = {}
                revdata["byte_count"] = 0
                revdata["packet_count"] = 0
                revdata["bytes_rate"] = 0
                revdata["packet_rate"] =0
                revdata["avg_packet_rate"] =0 
                revdata["avg_bytes_rate"] = 0


                if APP_TYPE==0:
                    #writecsv
                    write_csv(self.flowdb[key], revdata)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idletime=0, hardtime=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,  buffer_id=buffer_id,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        smac = src
        dmac = dst

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.arp_ip_to_port.setdefault(dpid, {})
        self.arp_ip_to_port[dpid].setdefault(in_port, [])
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)


        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                match = None

                if protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    srcport = t.src_port
                    dstport = t.dst_port
                    match = parser.OFPMatch(eth_dst=dmac, eth_src=smac,eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=srcport, tcp_dst=dstport,)

                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    srcport = u.src_port
                    dstport = u.dst_port
                    match = parser.OFPMatch(eth_dst=dmac, eth_src=smac,eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=srcport, udp_dst=dstport,)

                elif protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_dst=dmac, eth_src=smac,eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)



                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out  
                #flow_serial_no = get_flow_number(datapath.id)                
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, idletime=10,  buffer_id=msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match,  actions,idletime=10)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)





