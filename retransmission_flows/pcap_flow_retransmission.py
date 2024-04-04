import pyshark
import csv
import sys, os


##Generate Flow ID
def generate_flow_id(src_ip, dst_ip, src_port, dst_port, flows):
    flow_ids = ["{0}_{1}_{2}_{3}".format(src_ip, dst_ip, max(src_port, dst_port), min(src_port, dst_port)), "{0}_{1}_{2}_{3}".format(dst_ip, src_ip, max(src_port, dst_port), min(src_port, dst_port))]
    for flow_id in flow_ids:
        if flows.get(flow_id) is not None:
            return flow_id, False #Existing Flow
    
    return flow_ids[0], True #New flow  

# This will read all pcap file from a directory
def grab_pcap_files(directory):
    pcap_files = []
    for file in os.listdir(directory):
        if file.endswith(".pcap"):
            pcap_files.append(os.path.join(directory, file))
    return pcap_files


##Genrate Flows
def generate_flows_from_capture(capture):
        # Iterate over each packet
        flows = {}

        for packet in capture:      
            try:
                #Extracting Inf
                frame_number = packet.frame_info.number
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = packet[packet.transport_layer].srcport
                dst_port = packet[packet.transport_layer].dstport                   
                #add_packets_to_a_flow(frame_number, src_ip, dst_ip, src_port, dst_port)
                flow_id, is_new = generate_flow_id(src_ip, dst_ip, src_port, dst_port, flows)
                    #print(flow_id)
                if is_new is True:
                    flows[flow_id] = {
                        'flow_id': flow_id,
                        #'frame_number': [],
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'packet_count': 1
                    }
                else:
                    existing_packet_count = flows[flow_id]['packet_count']
                    flows[flow_id]['packet_count'] = existing_packet_count + 1  

            except AttributeError:
                # Handle packets that might not have the expected layers or fields
                #print("Packet does not contain all expected layers.")
                continue
        return flows

##Write to CSV files
def merge_and_write_to_csv(flows_v1, flows_v2, csv_file):
     
     with open(csv_file, 'w', newline='') as file:
            writer = csv.writer(file)
            # Write header
            writer.writerow(['Flow_ID', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Packet Count', 'Retransmission Packet Count'])

            for flow_id, flow in flows_v1.items():
                returnmission = 0 #defautl value is zero
                if flow_id in flows_v2:
                    returnmission = flows_v2.get(flow_id).get('packet_count', 0)

                writer.writerow([
                    flow_id, 
                    flow.get('src_ip'), 
                    flow.get('dst_ip'), 
                    flow.get('src_port'), 
                    flow.get('dst_port'),
                    flow.get('packet_count'),
                    returnmission
 
                ])  

#Read the pcap files
def convert_to_flows(directory):
    pcap_files = grab_pcap_files(directory)
    for pcap_file in pcap_files:           
        csv_file = "{0}_flows.csv".format(pcap_file) #generated csv files

        #this capture used for creating flows
        capture = pyshark.FileCapture(pcap_file)          
        flows_v1 = generate_flows_from_capture(capture)
        capture.close()

        #This capture is used to create flows for re-transmission
        capture = pyshark.FileCapture(pcap_file, display_filter='tcp.analysis.retransmission')      
        flows_v2 = generate_flows_from_capture(capture)
        capture.close()

        return merge_and_write_to_csv(flows_v1, flows_v2, csv_file)


if __name__ == "__main__":
    # Check if arguments are provided
    if len(sys.argv) > 1:
        # The first argument (sys.argv[0]) is the script name itself
        # The actual arguments start from sys.argv[1]
        directory = sys.argv[1]        
        # Print the argument
        print("Argument provided:", directory)
        convert_to_flows(directory)
    else:
        print("Please choose a pcap directory as an argument")
