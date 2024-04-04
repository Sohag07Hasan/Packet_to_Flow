import pyshark
import csv

# Path to your pcap file
file_path = 'Scenerio_1.1.pcapng'

# Create a capture object
capture = pyshark.FileCapture(file_path, display_filter='quic')

#CSV file to save data
outputfile = "output_flow.csv"

#Open the CSV file and write

#Contains all the flows
flows = {}


##Generate Flow ID
def generate_flow_id(src_ip, dst_ip, src_port, dst_port):
    flow_ids = ["{0}_{1}_{2}_{3}".format(src_ip, dst_ip, max(src_port, dst_port), min(src_port, dst_port)), "{0}_{1}_{2}_{3}".format(dst_ip, src_ip, max(src_port, dst_port), min(src_port, dst_port))]
    for flow_id in flow_ids:
        if flows.get(flow_id) is not None:
            return flow_id, False #Existing Flow
    
    return flow_ids[0], True #New flow


##This will add packets in a flow 
def add_packets_to_a_flow(frame_number, src_ip, dst_ip, src_port, dst_port, quic_connection_id, connection_number):
    flow_id, is_new = generate_flow_id(src_ip, dst_ip, src_port, dst_port) #gnerate a flow id

    if is_new is True:
        flows[flow_id] = {
            'flow_id': flow_id,
            'frame_number': [],
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'quic_connection_id': [quic_connection_id],
            'connection_number': [connection_number]
        }
    else:
        existing_quick_connection_id = flows[flow_id]['quic_connection_id']
        existing_connection_numbers = flows[flow_id]['connection_number']

        flows[flow_id]['frame_number'].append(frame_number)
        flows[flow_id]['quic_connection_id'].append(quic_connection_id) if quic_connection_id not in existing_quick_connection_id else None
        flows[flow_id]['connection_number'].append(quic_connection_id) if connection_number not in existing_connection_numbers else None

# Iterate over each packet
for packet in capture:        

    try:
        #Extracting Inf
        frame_number = packet.frame_info.number
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport

        # Extract QUIC Connection ID (if available)
        quic_connection_id = packet.quic.dcid if hasattr(packet.quic, 'dcid') else 'NA'
        connection_number = packet.quic.connection_number if hasattr(packet.quic, 'connection_number') else 'NA'            
            
        add_packets_to_a_flow(frame_number, src_ip, dst_ip, src_port, dst_port, quic_connection_id, connection_number)

    except AttributeError:
        # Handle packets that might not have the expected layers or fields
        #print("Packet does not contain all expected layers.")
        continue


with open(outputfile, 'w', newline='') as file:
    writer = csv.writer(file)

    # Write header
    writer.writerow(['Flow_ID', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'QUIC Connection ID', 'QUIC Connection Number', 'Frame Numbers'])

    for flow_id, flow in flows.items():
        #print(flow)
        writer.writerow([
            flow_id, 
            flow.get('src_ip'), 
            flow.get('dst_ip'), 
            flow.get('src_port'), 
            flow.get('dst_port'), 
            '__'.join(flow.get('quic_connection_id', [])), 
            '__'.join(flow.get('connection_number', [])), 
            len(flow.get('frame_number')) ])  

        

# Close the capture file
capture.close()
