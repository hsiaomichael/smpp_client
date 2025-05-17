import socket
import struct
import time

# SMPP server details
SMPP_SERVER = '127.0.0.1'
SMPP_PORT = 50000


# SMPP credentials
SYSTEM_ID = 'my_sys_id'
PASSWORD = 'my_passwd'
SYSTEM_TYPE = ''


sequence_number = 2

# SMPP constants
SMPP_VERSION = 0x34  # SMPP version 3.4
BIND_TRANSMITTER = 0x00000002
BIND_TRANSMITTER_RESP = 0x80000002
SUBMIT_SM = 0x00000004
SUBMIT_SM_RESP = 0x80000004
ESME_ROK = 0x00000000

# Status codes mapping (partial list)
STATUS_CODES = {
    ESME_ROK: "OK",
    0x00000001: "Message Length is invalid",
    0x00000002: "Command Length is invalid",
    0x00000003: "Invalid Command ID",
    0x00000004: "Incorrect BIND status for given command",
    0x00000005: "ESME Already in Bound State",
    0x00000006: "Invalid Priority Flag",
    0x00000007: "Invalid Registered Delivery Flag",
    0x00000008: "System Error",
    0x0000000A: "Invalid Source Address",
    0x0000000B: "Invalid Destination Address",
    0x0000000C: "Message ID is invalid",
    0x0000000D: "Bind Failed",
    0x0000000E: "Invalid Password",
    0x0000000F: "Invalid System ID",
    0x00000011: "Cancel SM Failed",
    0x00000013: "Replace SM Failed",
    0x00000014: "Message Queue Full",
    0x00000015: "Invalid Service Type",
    0x00000033: "Invalid number of destinations",
    0x00000034: "Invalid Distribution List name",
    0x00000040: "Destination flag is invalid (submit_multi)",
    0x00000042: "Invalid ‘submit with replace’ request",
    0x00000043: "Invalid esm_class field data",
    0x00000044: "Cannot Submit to Distribution List",
    0x00000045: "submit_sm or submit_multi failed",
    0x00000048: "Invalid Source address TON",
    0x00000049: "Invalid Source address NPI",
    0x00000050: "Invalid Destination address TON",
    0x00000051: "Invalid Destination address NPI",
    0x00000053: "Invalid system_type field",
    0x00000054: "Invalid replace_if_present flag",
    0x00000055: "Invalid number of messages",
    0x00000058: "Throttling error (ESME has exceeded allowed message limits)",
    0x00000061: "Invalid Scheduled Delivery Time",
    0x00000062: "Invalid message validity period (Expiry time)",
    0x00000063: "Predefined Message Invalid or Not Found",
    0x00000064: "ESME Receiver Temporary App Error Code",
    0x00000065: "ESME Receiver Permanent App Error Code",
    0x00000066: "ESME Receiver Reject Message Error Code",
    0x00000067: "query_sm request failed",
    0x000000C0: "Error in the optional part of the PDU Body.",
    0x000000C1: "Optional Parameter not allowed",
    0x000000C2: "Invalid Parameter Length.",
    0x000000C3: "Expected Optional Parameter missing",
    0x000000C4: "Invalid Optional Parameter Value",
    0x000000FE: "Delivery Failure (data_sm_resp)",
    0x000000FF: "Unknown Error"
}

def send_pdu(sock, pdu):
    try:
        sock.sendall(pdu)
    except Exception as e:
        print(f"Error sending PDU: {e}")
        raise

def read_pdu(sock):
    try:
        header = sock.recv(4)
        if len(header) < 4:
            raise IOError("Connection closed prematurely")
        length, = struct.unpack('>I', header)
        body = sock.recv(length - 4)
        return header + body
    except Exception as e:
        print(f"Error reading PDU: {e}")
        raise

def decode_bind_transmitter_resp(response):
    try:
        header = response[:16]
        body = response[16:]

        command_length, command_id, command_status, sequence_number = struct.unpack('>IIII', header)

        system_id = body.decode().split('\x00', 1)[0]

        return command_id, command_status, sequence_number, system_id
    except Exception as e:
        print(f"Error decoding bind_transmitter_resp: {e}")
        raise

def decode_submit_sm_resp(response):
    try:
        header = response[:16]
        body = response[16:]

        command_length, command_id, command_status, sequence_number = struct.unpack('>IIII', header)

        message_id = body.decode().split('\x00', 1)[0]

        return command_id, command_status, sequence_number, message_id
    except Exception as e:
        print(f"Error decoding submit_sm_resp: {e}")
        raise

def bind_transmitter(sock):
    try:
        sequence_number = 1

        # Prepare the body
        body = SYSTEM_ID.encode('ascii') + b'\x00' + \
               PASSWORD.encode('ascii') + b'\x00' + \
               SYSTEM_TYPE.encode('ascii') + b'\x00' + \
               struct.pack('B', SMPP_VERSION) + \
               struct.pack('B', 0x00) + \
               struct.pack('B', 0x00) + \
               b'\x00'  # Address range

        # Prepare the header
        command_length = 16 + len(body)
        pdu_header = struct.pack('>IIII', command_length, BIND_TRANSMITTER, 0, sequence_number)

        pdu = pdu_header + body
        send_pdu(sock, pdu)

        response = read_pdu(sock)
        command_id, command_status, sequence_number, system_id = decode_bind_transmitter_resp(response)

        if command_id == BIND_TRANSMITTER_RESP and command_status == ESME_ROK:
            print(f"Bind successful: system_id={system_id}")
            return True
        else:
            status_message = STATUS_CODES.get(command_status, "Unknown status")
            print(f"Bind failed: status={command_status} ({status_message})")
            return False

    except Exception as e:
        print(f"Error in bind_transmitter: {e}")
        raise

def submit_sm(sock,SOURCE_ADDR,DEST_ADDR,SHORT_MESSAGE):
    global sequence_number
    try:
        sequence_number = sequence_number + 1 
        if sequence_number > 10000:
           sequence_number = 1

        # Prepare the body
        service_type = b'\x00'
        source_addr_ton = struct.pack('B', 0x01)
        source_addr_npi = struct.pack('B', 0x01)
        source_addr = SOURCE_ADDR.encode('ascii') + b'\x00'
        dest_addr_ton = struct.pack('B', 0x01)
        dest_addr_npi = struct.pack('B', 0x01)
        destination_addr = DEST_ADDR.encode('ascii') + b'\x00'
        esm_class = struct.pack('B', 0x00)
        protocol_id = struct.pack('B', 0x00)
        priority_flag = struct.pack('B', 0x00)
        schedule_delivery_time = b'\x00'
        validity_period = b'\x00'
        registered_delivery = struct.pack('B', 0x00)
        replace_if_present_flag = struct.pack('B', 0x00)
        data_coding = struct.pack('B', 0x00)
        sm_default_msg_id = struct.pack('B', 0x00)
        sm_length = struct.pack('B', len(SHORT_MESSAGE))
        short_message = SHORT_MESSAGE.encode('ascii')

        body = service_type + \
               source_addr_ton + source_addr_npi + source_addr + \
               dest_addr_ton + dest_addr_npi + destination_addr + \
               esm_class + protocol_id + priority_flag + \
               schedule_delivery_time + validity_period + \
               registered_delivery + replace_if_present_flag + \
               data_coding + sm_default_msg_id + sm_length + short_message

        # Prepare the header
        command_length = 16 + len(body)
        pdu_header = struct.pack('>IIII', command_length, SUBMIT_SM, 0, sequence_number)

        pdu = pdu_header + body
        send_pdu(sock, pdu)

        response = read_pdu(sock)
        command_id, command_status, sequence_number, message_id = decode_submit_sm_resp(response)

        if command_id == SUBMIT_SM_RESP and command_status == ESME_ROK:
            print(f"Submit SM successful: message_id={message_id}")
        else:
            status_message = STATUS_CODES.get(command_status, "Unknown status")
            print(f"Submit SM failed: status={command_status} ({status_message})")

    except Exception as e:
        print(f"Error in submit_sm: {e}")
        raise

def main():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as smpp_socket:
            smpp_socket.connect((SMPP_SERVER, SMPP_PORT))


            print("Connected to SMPP server")
            if bind_transmitter(smpp_socket):
               
                for i in range(1):
                  SOURCE_ADDR = f'886765430{i:04d}'
                  DEST_ADDR = f'88665430{i:04d}'
                  SHORT_MESSAGE = f'Load test message {i:09d}'  # Adds a zero-padded integer suffix
                  submit_sm(smpp_socket,SOURCE_ADDR,DEST_ADDR,SHORT_MESSAGE)

            time.sleep(1)  # Wait for response
    except socket.error as e:
        print(f"Socket error: {e}")
    except IOError as e:
        print(f"I/O error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
