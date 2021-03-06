#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def writeIpv4Rules(p4info_helper, sw_id, dst_ip_addr, dst_mac_addr, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_mac_addr,
            "port": port
        })
    sw_id.WriteTableEntry(table_entry)
    print "Installed ingress forwarding rule on %s" % sw_id.name

def sendCPURules(p4info_helper, sw_id, dst_ip_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.send_to_cpu",
        action_params={
        })
    sw_id.WriteTableEntry(table_entry)
    print "Installed CPU rule on %s" % sw_id.name

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path, switch_id):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s' + switch_id,
            address='127.0.0.1:5005' + switch_id,
            device_id=int(switch_id)-1,
	        proto_dump_file="logs/s" + switch_id + "-p4runtime.log")

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)

    	if (sw.MasterArbitrationUpdate() == None):
            print "Failed to establish the connection"

        # Install the P4 program on the switches
        sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

        # Forward all packet to the controller (CPU_PORT 255)
        for i in range(1,3):
            if(i != sw.device_id + 1):
                writeIpv4Rules(p4info_helper, sw_id=sw, dst_ip_addr="10.0." + str(i) + "." + str(i), dst_mac_addr="08:00:00:00:0"+str(i)+":"+str(i)+str(i), port=2)
            else:
                writeIpv4Rules(p4info_helper, sw_id=sw, dst_ip_addr="10.0." + str(i) + "." + str(i), dst_mac_addr="08:00:00:00:0"+str(i)+":"+str(i)+str(i), port=1)

        sendCPURules(p4info_helper, sw_id=sw, dst_ip_addr="0.0.0.0")

        #read all table rules
    	readTableRules(p4info_helper, sw)
        while True:

            packetin = sw.PacketIn()	    #Packet in!
            if packetin is not None:
            	print "PACKET IN received"
            	print packetin
                packet = packetin.packet.payload
                packetout = p4info_helper.buildPacketOut(
                    payload = packet, #send the packet in you received back to output port 3!
                    metadata = {1: "\000\002"} #egress_spec (check @controller_header("packet_out") in the p4 code)
           	    )
                print "send PACKET OUT"
                print sw.PacketOut(packetout)
                packetin = None


    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    parser.add_argument('--switch-id', help='Switch ID number',
                        type=str, action='store', required=False)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found!" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found!" % args.bmv2_json
        parser.exit(2)
    main(args.p4info, args.bmv2_json, args.switch_id)
