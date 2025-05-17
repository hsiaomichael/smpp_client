
import socket
import logging
import struct

# Constants for SMPP Commands
BIND_TRANSCEIVER = 0x00000009
BIND_TRANSCEIVER_RESP = 0x80000009  # This is 2147483657 in decimal
SUBMIT_SM = 0x00000004
SUBMIT_SM_RESP = 0x80000004
DELIVER_SM = 0x00000005
GENERIC_NACK = 0x80000000
ENQUIRE_LINK = 0x00000015
ENQUIRE_LINK_RESP = 0x80000015
ESME_ROK = 0x00000000


# SMPP status codes dictionary for human-readable status decoding
SMPP_STATUS_CODES = {
    0x00000000: "OK",
    0x00000001: "Message length is invalid",
    0x00000002: "Command length is invalid",
    0x00000003: "Invalid command ID",
    0x00000004: "Incorrect bind status for given command",
    0x00000005: "ESME already in bound state",
    0x00000006: "Invalid priority flag",
    0x0000000A: "Invalid source address",
    0x0000000B: "Invalid destination address",
    0x0000000D: "Message queue full",
    0x0000000E: "Invalid service type",
    0x0000000F: "Invalid message ID",
    0x00000011: "Invalid TLV parameter",
    0x00000014: "Invalid bind status",
    0x00000015: "Invalid submit_sm parameters",
    0x00000021: "System error",
    0x00000032: "Network error",
    0x00000064: "Message rejected",
    # Add more status codes as needed
}




# Setup logging to capture unknown status codes
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def decode_status_code(status_code):
    """Return a human-readable string for SMPP status code."""
    status_message = SMPP_STATUS_CODES.get(status_code, "Unknown error")
    
    if status_message == "Unknown error":
        # Log unknown error code for further analysis
        logging.warning(f"Unknown SMPP status code: {status_code:#010x}")
    
    return status_message

def bind_transceiver(socket, system_id, password, system_type=''):
    """Send a bind_transceiver request to the SMSC."""
    interface_version = b'\x34'  # SMPP v3.4
    addr_ton = b'\x00'           # Type of Number: Unknown
    addr_npi = b'\x00'           # Numbering Plan Indicator: Unknown
    addr_range = b'\x00'         # Null-terminated empty string
    
    # Body: system_id, password, system_type, interface_version, addr_ton, addr_npi, addr_range
    body = (
        system_id.encode() + b'\x00' +
        password.encode() + b'\x00' +
        system_type.encode() + b'\x00' +
        interface_version + addr_ton + addr_npi + addr_range
    )
    
    # Sequence number starts with 1
    sequence_number = 1
    
    # Header: command_length, command_id, command_status, sequence_number
    command_length = 16 + len(body)  # Header is always 16 bytes
    command_id = BIND_TRANSCEIVER
    command_status = 0  # 0 = success
    
    # Pack header and body into the PDU
    header = struct.pack('>IIII', command_length, command_id, command_status, sequence_number)
    pdu = header + body
    
    # Send the PDU
    socket.sendall(pdu)
    
    # Human-readable output for debugging
    print("Sent bind_transceiver PDU with the following details:")
    print(f"  System ID: {system_id}")
    print(f"  Password: {password}")
    print(f"  System Type: {system_type}")
    print(f"  Interface Version: {interface_version.decode('utf-8')}")
    print(f"  Address TON: {ord(addr_ton)}")
    print(f"  Address NPI: {ord(addr_npi)}")
    print(f"  Address Range: {addr_range.decode('utf-8') if addr_range else '(empty)'}")
    print(f"  Sequence Number: {sequence_number}")
    
    # Debugging output for raw PDU
    #print(f"Raw PDU (for debugging): {pdu}")


def submit_sm(socket, source_addr, dest_addr, short_message, sequence_number):
    """Submit an SMS to the SMSC."""
    service_type = b'\x00'       # Null-terminated service type
    source_addr_ton = b'\x01'    # Source Addr TON (1 = International)
    source_addr_npi = b'\x01'    # Source Addr NPI (1 = ISDN, telephone number)
    dest_addr_ton = b'\x01'      # Dest Addr TON (1 = International)
    dest_addr_npi = b'\x01'      # Dest Addr NPI (1 = ISDN, telephone number)
    
    esm_class = b'\x00'          # Default ESM class
    protocol_id = b'\x00'        # Protocol ID
    priority_flag = b'\x00'      # Priority flag
    schedule_delivery_time = b'\x00'  # Null-terminated
    validity_period = b'\x00'         # Null-terminated
    registered_delivery = b'\x01'     # Request delivery receipt
    replace_if_present = b'\x00'      # Replace if present flag
    data_coding = b'\x00'             # Data coding (default)
    sm_default_msg_id = b'\x00'       # Default message ID
    
    # Short message length and content
    sm_length = struct.pack('B', len(short_message))
    sm_content = short_message.encode()

    # Build body
    body = (
        service_type +
        source_addr_ton + source_addr_npi + source_addr.encode() + b'\x00' +
        dest_addr_ton + dest_addr_npi + dest_addr.encode() + b'\x00' +
        esm_class + protocol_id + priority_flag +
        schedule_delivery_time + validity_period +
        registered_delivery + replace_if_present + data_coding + sm_default_msg_id +
        sm_length + sm_content
    )
    
    # Command ID for submit_sm is 0x00000004
    command_id = SUBMIT_SM
    
    # Header
    command_length = 16 + len(body)
    command_status = 0  # Success
    header = struct.pack('>IIII', command_length, command_id, command_status, sequence_number)
    
    pdu = header + body
    
    # Send the PDU
    socket.sendall(pdu)
    
    # Print the human-readable information
    print(f"Sent submit_sm PDU with:")
    print(f"  Source Addr: {source_addr}")
    print(f"  Destination Addr: {dest_addr}")
    print(f"  Message: {short_message}")
    print(f"  Sequence Number: {sequence_number}")
    #print(f"  PDU: {pdu}")

def decode_deliver_sm(response):
    try:
        header = response[:16]
        body = response[16:]

        command_length, command_id, command_status, sequence_number = struct.unpack('>IIII', header)

        # Parsing deliver_sm PDU according to SMPP 3.4 specification
        service_type_end = body.find(b'\x00')
        service_type = body[:service_type_end].decode('ascii')
        body = body[service_type_end + 1:]

        source_addr_ton = struct.unpack('B', body[0:1])[0]
        source_addr_npi = struct.unpack('B', body[1:2])[0]
        source_addr_end = body.find(b'\x00', 2)
        source_addr = body[2:source_addr_end].decode('ascii')
        body = body[source_addr_end + 1:]

        dest_addr_ton = struct.unpack('B', body[0:1])[0]
        dest_addr_npi = struct.unpack('B', body[1:2])[0]
        dest_addr_end = body.find(b'\x00', 2)
        dest_addr = body[2:dest_addr_end].decode('ascii')
        body = body[dest_addr_end + 1:]

        esm_class = struct.unpack('B', body[0:1])[0]
        protocol_id = struct.unpack('B', body[1:2])[0]
        priority_flag = struct.unpack('B', body[2:3])[0]
        schedule_delivery_time_end = body.find(b'\x00', 3)
        schedule_delivery_time = body[3:schedule_delivery_time_end].decode('ascii')
        body = body[schedule_delivery_time_end + 1:]

        validity_period_end = body.find(b'\x00')
        validity_period = body[:validity_period_end].decode('ascii')
        body = body[validity_period_end + 1:]

        registered_delivery = struct.unpack('B', body[0:1])[0]
        replace_if_present_flag = struct.unpack('B', body[1:2])[0]
        data_coding = struct.unpack('B', body[2:3])[0]
        sm_default_msg_id = struct.unpack('B', body[3:4])[0]
        sm_length = struct.unpack('B', body[4:5])[0]
        short_message = body[5:5 + sm_length].decode('ascii')

        return {
            "command_id": command_id,
            "command_status": command_status,
            "sequence_number": sequence_number,
            "service_type": service_type,
            "source_addr_ton": source_addr_ton,
            "source_addr_npi": source_addr_npi,
            "source_addr": source_addr,
            "dest_addr_ton": dest_addr_ton,
            "dest_addr_npi": dest_addr_npi,
            "dest_addr": dest_addr,
            "esm_class": esm_class,
            "protocol_id": protocol_id,
            "priority_flag": priority_flag,
            "schedule_delivery_time": schedule_delivery_time,
            "validity_period": validity_period,
            "registered_delivery": registered_delivery,
            "replace_if_present_flag": replace_if_present_flag,
            "data_coding": data_coding,
            "sm_default_msg_id": sm_default_msg_id,
            "sm_length": sm_length,
            "short_message": short_message
        }
    except Exception as e:
        print(f"Error decoding deliver_sm: {e}")
        raise


def handle_enquire_link(socket, pdu):
    try:
        header = pdu[:16]
        command_length, command_id, command_status, sequence_number = struct.unpack('>IIII', header)
        
        # Prepare enquire_link_resp
        pdu_header = struct.pack('>IIII', 16, ENQUIRE_LINK_RESP, ESME_ROK, sequence_number)
        socket.sendall(pdu_header)
        print("Enquire Link response sent")
    except Exception as e:
        print(f"Error handling enquire_link: {e}")
        raise

def read_response(socket):
    """Read response PDUs from the SMSC."""
    Status = 0

    while True:
        response = socket.recv(1024)
        if not response:
            break
        
        command_length, command_id, command_status, sequence_number = struct.unpack('>IIII', response[:16])
        print(f"-------------------------------------------------------------------------------------")
        if command_id == GENERIC_NACK:
            print(f"Received GENERIC_NACK, status: {decode_status_code(command_status)}")
        elif command_id == BIND_TRANSCEIVER_RESP:
            print(f"Received bind_transceiver_resp, status: {decode_status_code(command_status)}")
            # Parse optional system_id if present
            if len(response) > 16:
                system_id = response[16:].split(b'\x00', 1)[0].decode('utf-8')
                print(f"  System ID: {system_id}")


            # Check if the response was successful
            if command_status != 0:  # command_status is an integer, not part of the raw byte response
                print("Bind transceiver error!")
                break  # Exit or handle error as needed
            else:
                print("Bind transceiver successful!")
                Status = 1

       # If the bind was successful, exit the loop to proceed to submit_sm
        if Status == 1:
            print("Exiting read_response after successful bind.")
            break

        elif command_id == ENQUIRE_LINK:
            print("ENQUIRE_LINK: received")
            handle_enquire_link(socket, response)

        elif command_id == SUBMIT_SM_RESP:
            print(f"Received submit_sm_resp, status: {decode_status_code(command_status)}")
            if command_status != 0:
                print(f"Submit_SM failed with status: {decode_status_code(command_status)}")
            else:
                print("Submit_SM successful!")
        elif command_id == DELIVER_SM:
            print(f"Delivery_SM received for Sequence: {sequence_number}")
            
        
            # Parse delivery report details (optional)
            if len(response) > 16:

              result = decode_deliver_sm(response)
              print(f"Received Deliver SM:\n"
              f"  Command ID: {result['command_id']}\n"
              f"  Command Status: {result['command_status']} ({SMPP_STATUS_CODES.get(result['command_status'], 'Unknown')})\n"
              f"  Sequence Number: {result['sequence_number']}\n"
              f"  Service Type: {result['service_type']}\n"
              f"  Source Address TON: {result['source_addr_ton']}\n"
              f"  Source Address NPI: {result['source_addr_npi']}\n"
              f"  Source Address: {result['source_addr']}\n"
              f"  Destination Address TON: {result['dest_addr_ton']}\n"
              f"  Destination Address NPI: {result['dest_addr_npi']}\n"
              f"  Destination Address: {result['dest_addr']}\n"
              f"  ESM Class: {result['esm_class']}\n"
              f"  Protocol ID: {result['protocol_id']}\n"
              f"  Priority Flag: {result['priority_flag']}\n"
              f"  Schedule Delivery Time: {result['schedule_delivery_time']}\n"
              f"  Validity Period: {result['validity_period']}\n"
              f"  Registered Delivery: {result['registered_delivery']}\n"
              f"  Replace If Present Flag: {result['replace_if_present_flag']}\n"
              f"  Data Coding: {result['data_coding']}\n"
              f"  SM Default Msg ID: {result['sm_default_msg_id']}\n"
              f"  SM Length: {result['sm_length']}\n"
              f"  Short Message: {result['short_message']}")
                      
            # Send DELIVER_SM_RESP to acknowledge the DELIVER_SM
            # Construct DELIVER_SM_RESP PDU to acknowledge the receipt of the message
            command_length = 17
        
            # Verify the PDU header construction
            pdu_header = struct.pack('>IIII', command_length, 0x80000005, 0, sequence_number)
            # Add the 0x00 byte to the PDU
            pdu_body = b'\x00'
            deliver_sm_resp = pdu_header + pdu_body

            socket.sendall(deliver_sm_resp)

            print(f"Sent DELIVER_SM_RESP with sequence number {sequence_number}")

        else:
            print(f"Received unknown PDU, Command ID: {command_id}")



    return Status

def main():
    # Define SMSC connection parameters
    smsc_host = "127.0.0.1"
    smsc_port = 50000

    # SMPP credentials
    system_id = "my_system_id1"
    password = "my_passwd"
    source_addr = '886928090991'
    dest_addr = '00050'  # Recipient phone number
    short_message = 'This test message submit to SMSC '  # Message content
    
    # Establish a TCP connection to the SMSC
    smsc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    smsc_socket.connect((smsc_host, smsc_port))
    
    # Step 1: Bind as a transceiver
    bind_transceiver(smsc_socket, system_id, password)
    bind_response = read_response(smsc_socket)
    print(f"Print bind result {bind_response}") 
    if bind_response == 1 :
      # Step 2: Submit a message    
      print(f"-------------------------------------------------------------------------------------")
      print(f"Send SMPP Submit_sm")
      submit_sm(smsc_socket, source_addr, dest_addr, short_message, sequence_number=2)
    
    print(f"looping read_response")
    # Step 3: Wait and read responses (including delivery reports)
    read_response(smsc_socket)


if __name__ == "__main__":
    main()
