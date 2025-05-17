import socket
import struct
import threading
import random
import signal
import sys
import logging
from datetime import datetime
import time

# SMPP constants (command ids, response ids)
BIND_RECEIVER = 0x00000001
BIND_TRANSMITTER = 0x00000002
BIND_TRANSCIEVER = 0x00000009
BIND_RECEIVER_RESP = 0x80000001
BIND_TRANSMITTER_RESP = 0x80000002
BIND_TRANSCIEVER_RESP = 0x80000009
SUBMIT_SM = 0x00000004
SUBMIT_SM_RESP = 0x80000004
DELIVER_SM = 0x00000005
DELIVER_SM_RESP = 0x80000005
ENQUIRE_LINK = 0x00000015
ENQUIRE_LINK_RESP = 0x80000015
UNBIND = 0x00000006
UNBIND_RESP = 0x80000006
GENERIC_NACK = 0x80000000


connected_clients = []
# Global variable for maximum concurrent connections (threads)
MAX_CONCURRENT_THREADS =500
thread_semaphore = threading.Semaphore(MAX_CONCURRENT_THREADS)
running_threads = []

submit_sm_store = {}
submit_sm_store_lock = threading.Lock()

# Setup logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(filename)s:%(lineno)d] Thread ID: %(thread)d - %(levelname)s - %(message)s ',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class SMPPServer:
    def __init__(self, host='', port=50001):
        self.host = host
        self.port = port
        self.server_socket = None
        self.shutdown_flag = threading.Event()  # Add shutdown flag
        self.cleanup_lock = threading.Lock()
        self.sequence_number = 1  # Initialize sequence number

    def get_next_sequence_number(self):
        with threading.Lock():
            seq_no = self.sequence_number
            self.sequence_number += 1
            if self.sequence_number > 0x0FFFFFFF:  # Reset if it exceeds the max value for a 4-byte integer
                self.sequence_number = 1
            return seq_no
            
    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logger.info(f"SMPP Server started on {self.host}:{self.port}...")

        while not self.shutdown_flag.is_set():
            try:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"Client connected: {client_address}")
                connected_clients.append(client_socket)

                if thread_semaphore.acquire(blocking=False):
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                    client_thread.daemon = True
                    client_thread.start()
                    running_threads.append(client_thread)
                else:
                    logger.warning(f"Max concurrent connections reached. Denying new connection from {client_address}")
                    client_socket.close()
            except KeyboardInterrupt:
                logger.info("Server interrupted by user. Shutting down gracefully.")
                self.cleanup()
                break
		

				
    def parse_pdu(self,pdu):
        try:
            command_length, command_id, command_status, sequence_number = struct.unpack('!IIII', pdu[:16])
            parsed_pdu = {
                'command_length': command_length,
                'command_id': command_id,
                'command_status': command_status,
                'sequence_number': sequence_number
            }
    
            if command_id in [BIND_RECEIVER_RESP, BIND_TRANSMITTER_RESP, BIND_TRANSCIEVER_RESP]:
                system_id = pdu[16:].decode('ascii').strip('\x00')
                parsed_pdu['system_id'] = system_id
            elif command_id == SUBMIT_SM_RESP:
                message_id = pdu[16:].decode('ascii').strip('\x00')
                parsed_pdu['message_id'] = message_id
            elif command_id == DELIVER_SM_RESP:
                message_id = pdu[16:].decode('ascii').strip('\x00')
                parsed_pdu['message_id'] = message_id
            elif command_id == ENQUIRE_LINK_RESP:
                # No body for ENQUIRE_LINK_RESP
                pass
            elif command_id == UNBIND_RESP:
                # No body for UNBIND_RESP
                pass
            elif command_id == GENERIC_NACK:
                # No body for GENERIC_NACK
                pass
            elif command_id in [BIND_RECEIVER, BIND_TRANSMITTER, BIND_TRANSCIEVER]:
                system_id_end = pdu.find(b'\x00', 16)
                system_id = pdu[16:system_id_end].decode('ascii')
                password_start = system_id_end + 1
                password_end = pdu.find(b'\x00', password_start)
                password = pdu[password_start:password_end].decode('ascii')
                system_type_start = password_end + 1
                system_type_end = pdu.find(b'\x00', system_type_start)
                system_type = pdu[system_type_start:system_type_end].decode('ascii')
                interface_version, addr_ton, addr_npi = struct.unpack('!BBB', pdu[system_type_end + 1:system_type_end + 4])
                address_range_start = system_type_end + 4
                address_range_end = pdu.find(b'\x00', address_range_start)
                address_range = pdu[address_range_start:address_range_end].decode('ascii')
                parsed_pdu.update({
                    'system_id': system_id,
                    'password': password,
                    'system_type': system_type,
                    'interface_version': interface_version,
                    'addr_ton': addr_ton,
                    'addr_npi': addr_npi,
                    'address_range': address_range
                })
            elif command_id == SUBMIT_SM:
                service_type_end = pdu.find(b'\x00', 16)
                service_type = pdu[16:service_type_end].decode('ascii')
                source_addr_ton, source_addr_npi = struct.unpack('!BB', pdu[service_type_end + 1:service_type_end + 3])
                source_addr_start = service_type_end + 3
                source_addr_end = pdu.find(b'\x00', source_addr_start)
                source_addr = pdu[source_addr_start:source_addr_end].decode('ascii')
                dest_addr_ton, dest_addr_npi = struct.unpack('!BB', pdu[source_addr_end + 1:source_addr_end + 3])
                dest_addr_start = source_addr_end + 3
                dest_addr_end = pdu.find(b'\x00', dest_addr_start)
                dest_addr = pdu[dest_addr_start:dest_addr_end].decode('ascii')
                esm_class, protocol_id, priority_flag = struct.unpack('!BBB', pdu[dest_addr_end + 1:dest_addr_end + 4])
                schedule_delivery_time_start = dest_addr_end + 4
                schedule_delivery_time_end = pdu.find(b'\x00', schedule_delivery_time_start)
                schedule_delivery_time = pdu[schedule_delivery_time_start:schedule_delivery_time_end].decode('ascii')
                validity_period_start = schedule_delivery_time_end + 1
                validity_period_end = pdu.find(b'\x00', validity_period_start)
                validity_period = pdu[validity_period_start:validity_period_end].decode('ascii')
                registered_delivery, replace_if_present_flag, data_coding, sm_default_msg_id, sm_length = struct.unpack(
                    '!BBBBB', pdu[validity_period_end + 1:validity_period_end + 6])
                short_message_start = validity_period_end + 6
                short_message = pdu[short_message_start:short_message_start + sm_length].decode('ascii')
                
                parsed_pdu.update({
                    'service_type': service_type,
                    'source_addr_ton': source_addr_ton,
                    'source_addr_npi': source_addr_npi,
                    'source_addr': source_addr,
                    'dest_addr_ton': dest_addr_ton,
                    'dest_addr_npi': dest_addr_npi,
                    'dest_addr': dest_addr,
                    'esm_class': esm_class,
                    'protocol_id': protocol_id,
                    'priority_flag': priority_flag,
                    'schedule_delivery_time': schedule_delivery_time,
                    'validity_period': validity_period,
                    'registered_delivery': registered_delivery,
                    'replace_if_present_flag': replace_if_present_flag,
                    'data_coding': data_coding,
                    'sm_default_msg_id': sm_default_msg_id,
                    'sm_length': sm_length,
                    'short_message': short_message
                })
            elif command_id == DELIVER_SM:
                service_type_end = pdu.find(b'\x00', 16)
                service_type = pdu[16:service_type_end].decode('ascii')
                source_addr_ton, source_addr_npi = struct.unpack('!BB', pdu[service_type_end + 1:service_type_end + 3])
                source_addr_start = service_type_end + 3
                source_addr_end = pdu.find(b'\x00', source_addr_start)
                source_addr = pdu[source_addr_start:source_addr_end].decode('ascii')
                dest_addr_ton, dest_addr_npi = struct.unpack('!BB', pdu[source_addr_end + 1:source_addr_end + 3])
                dest_addr_start = source_addr_end + 3
                dest_addr_end = pdu.find(b'\x00', dest_addr_start)
                dest_addr = pdu[dest_addr_start:dest_addr_end].decode('ascii')
                
                esm_class, protocol_id, priority_flag = struct.unpack('!BBB', pdu[dest_addr_end + 1:dest_addr_end + 4])
                schedule_delivery_time_start = dest_addr_end + 4
                schedule_delivery_time_end = pdu.find(b'\x00', schedule_delivery_time_start)
                schedule_delivery_time = pdu[schedule_delivery_time_start:schedule_delivery_time_end].decode('ascii')
                validity_period_start = schedule_delivery_time_end + 1
                validity_period_end = pdu.find(b'\x00', validity_period_start)
                validity_period = pdu[validity_period_start:validity_period_end].decode('ascii')
                registered_delivery, replace_if_present_flag, data_coding, sm_default_msg_id, sm_length = struct.unpack(
                    '!BBBBB', pdu[validity_period_end + 1:validity_period_end + 6])
                short_message_start = validity_period_end + 6
                short_message = pdu[short_message_start:short_message_start + sm_length].decode('ascii')
                
                parsed_pdu.update({
                    'service_type': service_type,
                    'source_addr_ton': source_addr_ton,
                    'source_addr_npi': source_addr_npi,
                    'source_addr': source_addr,
                    'dest_addr_ton': dest_addr_ton,
                    'dest_addr_npi': dest_addr_npi,
                    'dest_addr': dest_addr,
                    'esm_class': esm_class,
                    'protocol_id': protocol_id,
                    'priority_flag': priority_flag,
                    'schedule_delivery_time': schedule_delivery_time,
                    'validity_period': validity_period,
                    'registered_delivery': registered_delivery,
                    'replace_if_present_flag': replace_if_present_flag,
                    'data_coding': data_coding,
                    'sm_default_msg_id': sm_default_msg_id,
                    'sm_length': sm_length,
                    'short_message': short_message
                })
                
                 
                optional_params_start = short_message_start + sm_length
                while optional_params_start < command_length:
                     tag, length = struct.unpack('!HH', pdu[optional_params_start:optional_params_start + 4])
                     value = pdu[optional_params_start + 4:optional_params_start + 4 + length]
                     if tag == 0x001E:  # receipted_message_id
                         parsed_pdu.update({'receipted_message_id': value.decode('ascii').strip('\x00')})
                     elif tag == 0x0427:  # message_state
                         parsed_pdu.update({'message_state': struct.unpack('!B', value)[0]})
                     optional_params_start += 4 + length
            else:
                parsed_pdu['body'] = pdu[16:].hex()
    
            return parsed_pdu
        except Exception as e:
            logger.error(f"Error parsing PDU: {e}")
            return None
    		
		
    def handle_client(self, client_socket):
        try:
            while not self.shutdown_flag.is_set():  # Check the shutdown flag
                header = self.read_exactly(client_socket, 16)
                if len(header) < 16:
                    if len(header) == 0:
                        logger.info("Client disconnected.")
                    else:
                        logger.error(f"Received incomplete header. Data length={len(header)}")
                    break

                #logger.info(f"Received header: {header.hex()}")
                logger.info(f"---------------------------------------------------------------------------------")
                command_length, command_id, command_status, sequence_number = struct.unpack('!IIII', header[:16])
                logger.info(f"Parsed header: command_length={command_length}, command_id={command_id}, command_status={command_status}, sequence_number={sequence_number}")

                body_length = command_length - 16
                body = self.read_exactly(client_socket, body_length)
                #logger.info(f"Received body: {body.hex()}")
                
                 # Validate command length
                if command_length != 16 + len(body):
                    logger.error(f"Invalid command length: expected {command_length}, got {16 + len(body)}")
                    nack_resp = self.create_nack_response(sequence_number)
                    client_socket.send(nack_resp)
                    client_socket.close()  # Disconnect the client
                    if client_socket in connected_clients:
                      connected_clients.remove(client_socket)  # Remove client from the list
                    break

                if command_id in [BIND_RECEIVER, BIND_TRANSMITTER, BIND_TRANSCIEVER]:
                    self.handle_bind(client_socket, command_id, sequence_number, body)
                elif command_id == SUBMIT_SM:
                    self.handle_submit_sm(client_socket, sequence_number, body)
                elif command_id == ENQUIRE_LINK:
                    self.handle_enquire_link(client_socket, sequence_number)
                elif command_id == UNBIND:
                    self.handle_unbind(client_socket, sequence_number)
                elif command_id == UNBIND_RESP:  # Add handling for UNBIND_RESP
                    logger.info(f"Received UNBIND_RESP for sequence_number={sequence_number}")   
                elif command_id == DELIVER_SM_RESP:  
                
                    logger.info(f"Received DELIVER_SM_RESP for sequence_number={sequence_number}")   
                    #logger.info(f"DELIVER_SM_RESP: {self.parse_pdu(submit_sm_resp)}")  
                    self.handle_deliver_sm_resp(client_socket, sequence_number,body)  
                elif command_id == GENERIC_NACK:
                    logger.info(f"Received GENERIC_NACK for sequence_number={sequence_number} close connection")  
                    client_socket.close()  # Disconnect the client 
                    if client_socket in connected_clients:
                      connected_clients.remove(client_socket)  # Remove client from the list
                    break
           
                else:
                    logger.warning(f"Received unknown command ID {command_id}. Full header: {header.hex()}")
                    self.handle_unknown_command(client_socket, header)

        except socket.error as e:
            logger.error(f"Socket error: {e}")
        except struct.error as e:
            logger.error(f"Struct unpacking error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            thread_semaphore.release()
            client_socket.close()
            if client_socket in connected_clients:
              connected_clients.remove(client_socket)  # Remove client from the list
            logger.info("Client connection closed and removed from the list.")

    def read_exactly(self, client_socket, length):
        data = b''
        while len(data) < length:
            packet = client_socket.recv(length - len(data))
            if not packet:
                break
            data += packet
        #logger.info(f"Received data: {data.hex()}")  # Print the received data
        return data
        
        
   
    

    def handle_bind(self, client_socket, command_id, sequence_number, body):
        #logger.info(f"Received BIND request: {body.hex()}")

        try:
            system_id_end = body.find(b'\x00')
            if system_id_end == -1:
                raise ValueError("System ID is not null-terminated.")
            system_id = body[:system_id_end].decode('ascii')

            password_start = system_id_end + 1
            password_end = body.find(b'\x00', password_start)
            if password_end == -1:
                raise ValueError("Password is not null-terminated.")
            password = body[password_start:password_end].decode('ascii')

            system_type_start = password_end + 1
            system_type_end = body.find(b'\x00', system_type_start)
            if system_type_end == -1:
                raise ValueError("System type is not null-terminated.")
            system_type = body[system_type_start:system_type_end].decode('ascii')

            interface_version = body[system_type_end + 1]
            addr_ton = body[system_type_end + 2]
            addr_npi = body[system_type_end + 3]

            address_range_start = system_type_end + 4
            address_range_end = body.find(b'\x00', address_range_start)
            if address_range_end == -1:
                address_range_end = len(body)
            address_range = body[address_range_start:address_range_end].decode('ascii')

            

            # Determine the correct response command ID
            if command_id == BIND_RECEIVER:
                response_command_id = BIND_RECEIVER_RESP
                bind_type = "BIND_RECEIVER"
            elif command_id == BIND_TRANSCIEVER:
                response_command_id = BIND_TRANSCIEVER_RESP
                bind_type = "BIND_TRANSCEIVER"
            elif command_id == BIND_TRANSMITTER:
                response_command_id = BIND_TRANSMITTER_RESP
                bind_type = "BIND_TRANSMITTER"
            else:
                raise ValueError(f"Unsupported BIND command ID: {command_id}")

            logger.info(
                f"{bind_type} request: system_id={system_id}, password={password}, "
                f"system_type={system_type}, interface_version={interface_version}, "
                f"addr_ton={addr_ton}, addr_npi={addr_npi}, address_range={address_range}"
            )
            #logger.info(f"Handling {bind_type} for system_id={system_id}")

            # Construct the response PDU according to SMPP 3.4 spec
            system_id_resp = system_id.encode('ascii') + b'\x00'
            command_length = 16 + len(system_id_resp)  # Header + body
            response = struct.pack(
                '!IIII', command_length, response_command_id, 0, sequence_number
            ) + system_id_resp
            logger.info(f"Sent {bind_type} response: {self.parse_pdu(response)}") 
			
            client_socket.send(response)
           
			
        except Exception as e:
            logger.error(f"Error parsing BIND request: {e}")
            nack_resp = self.create_nack_response(sequence_number)
            client_socket.send(nack_resp)
            logger.info(f"Sent NACK response: {nack_resp.hex()}")

    def handle_submit_sm(self, client_socket, sequence_number, body):
        #logger.info(f"Received SUBMIT_SM request: {body.hex()}")

        try:
            service_type_end = body.find(b'\x00')
            if service_type_end == -1:
                raise ValueError("Service type is not null-terminated.")
            service_type = body[:service_type_end].decode('ascii')

            source_addr_ton = body[service_type_end + 1]
            source_addr_npi = body[service_type_end + 2]

            source_addr_start = service_type_end + 3
            source_addr_end = body.find(b'\x00', source_addr_start)
            if source_addr_end == -1:
                raise ValueError("Source address is not null-terminated.")
            source_addr = body[source_addr_start:source_addr_end].decode('ascii')

            dest_addr_ton = body[source_addr_end + 1]
            dest_addr_npi = body[source_addr_end + 2]

            dest_addr_start = source_addr_end + 3
            dest_addr_end = body.find(b'\x00', dest_addr_start)
            if dest_addr_end == -1:
                raise ValueError("Destination address is not null-terminated.")
            dest_addr = body[dest_addr_start:dest_addr_end].decode('ascii')

            esm_class = body[dest_addr_end + 1]
            protocol_id = body[dest_addr_end + 2]
            priority_flag = body[dest_addr_end + 3]

            schedule_delivery_time_start = dest_addr_end + 4
            schedule_delivery_time_end = body.find(b'\x00', schedule_delivery_time_start)
            if schedule_delivery_time_end == -1:
                raise ValueError("Schedule delivery time is not null-terminated.")
            schedule_delivery_time = body[schedule_delivery_time_start:schedule_delivery_time_end].decode('ascii')
        
            validity_period_start = schedule_delivery_time_end + 1
            validity_period_end = body.find(b'\x00', validity_period_start)
            if validity_period_end == -1:
                raise ValueError("Validity period is not null-terminated.")
            validity_period = body[validity_period_start:validity_period_end].decode('ascii')
        
            registered_delivery = body[validity_period_end + 1]
            replace_if_present_flag = body[validity_period_end + 2]
            data_coding = body[validity_period_end + 3]
            sm_default_msg_id = body[validity_period_end + 4]
            sm_length = body[validity_period_end + 5]
        
            short_message_start = validity_period_end + 6
            short_message = body[short_message_start:short_message_start + sm_length].decode('ascii')
            
            submit_sm_resp,message_id = self.create_submit_sm_response(sequence_number)
            client_socket.send(submit_sm_resp)
            logger.info(f"Sent SubmitSM response: {self.parse_pdu(submit_sm_resp)}")
            
            #logger.info(f"handle submit function dest_addr: {dest_addr}")
            parsed_pdu = {
                'service_type': service_type,
                'source_addr_ton': source_addr_ton,
                'source_addr_npi': source_addr_npi,
                'source_addr': source_addr,
                'dest_addr_ton': dest_addr_ton,
                'dest_addr_npi': dest_addr_npi,
                'dest_addr': dest_addr,
                'esm_class': esm_class,
                'protocol_id': protocol_id,
                'priority_flag': priority_flag,
                'schedule_delivery_time': schedule_delivery_time,
                'validity_period': validity_period,
                'registered_delivery': registered_delivery,
                'replace_if_present_flag': replace_if_present_flag,
                'data_coding': data_coding,
                'sm_default_msg_id': sm_default_msg_id,
                'sm_length': sm_length,
                'short_message': short_message,
                'message_id': message_id
            }
        
            logger.info(
                f"Parsed SUBMIT_SM: service_type={service_type}, source_addr_ton={source_addr_ton}, "
                f"source_addr_npi={source_addr_npi}, source_addr={source_addr}, dest_addr_ton={dest_addr_ton}, "
                f"dest_addr_npi={dest_addr_npi}, dest_addr={dest_addr}, esm_class={esm_class}, "
                f"protocol_id={protocol_id}, priority_flag={priority_flag}, schedule_delivery_time={schedule_delivery_time}, "
                f"validity_period={validity_period}, registered_delivery={registered_delivery}, "
                f"replace_if_present_flag={replace_if_present_flag}, data_coding={data_coding}, "
                f"sm_default_msg_id={sm_default_msg_id}, sm_length={sm_length}, short_message={short_message},message_id={message_id}"
            )

            
            submit_date = datetime.now().strftime('%y%m%d%H%M')
            parsed_pdu['submit_date'] = submit_date
            with submit_sm_store_lock:
              submit_sm_store[sequence_number] = parsed_pdu  # Highlighted change
            
            # Create and send DELIVER_SM with delivery report
            deliver_sm = self.create_deliver_sm(sequence_number)
            #logger.info(f"deliver_sm pdu: {deliver_sm.hex()}")
            client_socket.send(deliver_sm)
            logger.info(f"Sent DeliverSM with delivery report: {self.parse_pdu(deliver_sm)}")
        
            
        except Exception as e:
            logger.error(f"Error parsing SUBMIT_SM: {e}")
            nack_resp = self.create_nack_response(sequence_number)
            client_socket.send(nack_resp)
            
    def create_deliver_sm(self, sequence_number):
        try:
            # Retrieve the stored information
            with submit_sm_store_lock:
                if sequence_number not in submit_sm_store:
                    raise ValueError("Missing stored information for sequence number")
                stored_info = submit_sm_store.pop(sequence_number)  # Remove the entry after retrieving it
                
            submit_date = stored_info['submit_date']
            
            done_date = datetime.now().strftime('%y%m%d%H%M')
            first_5_char_of_sms_text = stored_info['short_message'][:5]
            # Construct the delivery report message
            #delivery_report = f"id:{stored_info['message_id']} sub:001 dlvrd:001 submit date:{submit_date} done date:{done_date} stat:DELIVRD err:000 text:"
            delivery_report = f"id:{stored_info['message_id']} sub:001 dlvrd:001 submit date:YYMMDDhhmm done date:YYMMDDhhmm stat:DELIVRD err:000 text:{first_5_char_of_sms_text}"
            # Encode the delivery report message
            delivery_report_bytes = delivery_report.encode('ascii')
            #logger.info(f"delivery_report_bytes: {delivery_report_bytes.hex()}")
            sm_length = len(delivery_report_bytes)
            #logger.info(f"sm_length: {sm_length}")

            # Optional parameters encoded as TLV
            receipted_message_id = stored_info['message_id'].encode('ascii') + b'\x00'
            #logger.info(f"receipted_message_id : {receipted_message_id}")
            receipted_message_id_tlv = struct.pack('!HH', 0x001E, len(receipted_message_id)) + receipted_message_id
            #logger.info(f"Received receipted_message_id_tlv request: {receipted_message_id_tlv.hex()}")
            message_state_tlv = struct.pack('!HHB', 0x0427, 1, 2) # Assuming 'DELIVRD' state
            #logger.info(f"message_state_tlv request: {message_state_tlv.hex()}")


            #logger.info(f"create_deliver_sm function dest_addr: {stored_info['dest_addr']}")
            
            # Construct the DELIVER_SM PDU
            # Calculate command_length
            command_length = (
            16 +  # Header
            len(stored_info['service_type'].encode('ascii')) + 1 +  # Service Type
            1 + 1 +  # Source Address TON and NPI
            len(stored_info['source_addr'].encode('ascii')) + 1 +  # Source Address
            1 + 1 +  # Destination Address TON and NPI
            len(stored_info['dest_addr'].encode('ascii')) + 1 +  # Destination Address
            1 + 1 + 1 +  # ESM Class, Protocol ID, Priority Flag
            len(stored_info['schedule_delivery_time'].encode('ascii')) + 1 +  # Schedule Delivery Time
            1 +  # Validity Period
            1 + 1 + 1 + 1 +  # Registered Delivery, Replace If Present Flag, Data Coding, SM Default Msg ID
            1 +  # SM Length
            sm_length +  # Short Message
            len(receipted_message_id_tlv) +  # Optional Parameter: receipted_message_id
            len(message_state_tlv)  # Optional Parameter: message_state
            )
            
            sequence_number = self.get_next_sequence_number()
            deliver_sm_pdu_old = struct.pack(
                '!IIII', command_length, DELIVER_SM, 0, sequence_number
            ) +  stored_info['service_type'].encode('ascii') + b'\x00'+struct.pack(
                '!BB', stored_info['source_addr_ton'], stored_info['source_addr_npi']
            ) + stored_info['source_addr'].encode('ascii') + b'\x00' + struct.pack(
                '!BB', stored_info['dest_addr_ton'], stored_info['dest_addr_npi']
            ) + stored_info['dest_addr'].encode('ascii') + b'\x00' + struct.pack(
                '!BBB', stored_info['esm_class'], stored_info['protocol_id'], stored_info['priority_flag']
            ) + stored_info['schedule_delivery_time'].encode('ascii') + b'\x00' + stored_info['validity_period'].encode('ascii') + b'\x00' + struct.pack(
                '!BBB', stored_info['registered_delivery'], stored_info['replace_if_present_flag'], stored_info['data_coding']
            ) + struct.pack('!B', stored_info['sm_default_msg_id']) + struct.pack('!B', sm_length) + delivery_report_bytes + receipted_message_id_tlv + message_state_tlv


            deliver_sm_pdu = struct.pack(
                '!IIII', command_length, DELIVER_SM, 0, sequence_number
            ) +  stored_info['service_type'].encode('ascii') + b'\x00'+struct.pack(
                '!BB', stored_info['dest_addr_ton'], stored_info['dest_addr_npi']
            ) + stored_info['dest_addr'].encode('ascii') + b'\x00' + struct.pack(
                '!BB', stored_info['source_addr_ton'], stored_info['source_addr_npi']
            ) + stored_info['source_addr'].encode('ascii') + b'\x00' + struct.pack(
                '!BBB', 0x04, stored_info['protocol_id'], stored_info['priority_flag']
            ) + stored_info['schedule_delivery_time'].encode('ascii') + b'\x00' + b'\x00' + struct.pack(
                '!BBB', stored_info['registered_delivery'], stored_info['replace_if_present_flag'], stored_info['data_coding']
            ) + struct.pack('!B', stored_info['sm_default_msg_id']) + struct.pack('!B', sm_length) + delivery_report_bytes + receipted_message_id_tlv + message_state_tlv
            # Sleep for 0.01 seconds before sending the response
            time.sleep(0.01)
            return deliver_sm_pdu
        except Exception as e:
            logger.error(f"Error creating DELIVER_SM: {e}")
            return b''
            
    def handle_deliver_sm_resp(self, client_socket, sequence_number, body):
        logger.info(f"Received DELIVER_SM_RESP request: {body.hex()}")

        try:
            # Parse the DELIVER_SM_RESP PDU
            parsed_pdu = self.parse_pdu(body)
            #logger.info(f"Parsed DELIVER_SM_RESP: {parsed_pdu}")

           
            #logger.info(
            #    f"DELIVER_SM_RESP received:  sequence_number={sequence_number}"
            #)

            # Handle the response as needed (e.g., update delivery status, log information, etc.)
            # For this example, we'll just log the information

        except Exception as e:
            logger.error(f"Error handling DELIVER_SM_RESP: {e}")        
            
    def handle_enquire_link(self, client_socket, sequence_number):
        #logger.info("Handling ENQUIRE_LINK request...")

        try:
            command_length = 16  # Header only, no body for ENQUIRE_LINK_RESP
            enquire_link_resp = struct.pack('!IIII',  command_length, ENQUIRE_LINK_RESP,0, sequence_number)
            client_socket.send(enquire_link_resp)
            #logger.info(f"Sent ENQUIRE_LINK_RESP response: {enquire_link_resp.hex()}")
            logger.info(f"Sent ENQUIRE_LINK_RESP response: {self.parse_pdu(enquire_link_resp)}")
        except Exception as e:
            logger.error(f"Error handling ENQUIRE_LINK: {e}")

    def handle_unbind(self, client_socket, sequence_number):
        logger.info("Handling UNBIND request...")

        try:
            command_length = 16  # Header only, no body for UNBIND_RESP
            unbind_resp = struct.pack('!IIII', command_length, UNBIND_RESP, 0, sequence_number)
            client_socket.send(unbind_resp)
            logger.info(f"Sent UNBIND_RESP response: {unbind_resp.hex()}")
        except Exception as e:
            logger.error(f"Error handling UNBIND: {e}")

    def handle_unknown_command(self, client_socket, header):
        logger.warning(f"Unknown command received: {header.hex()}")

        try:
            command_length = 16  # Header only, no body for GENERIC_NACK
            invalid_resp = struct.pack('!IIII',  command_length, GENERIC_NACK,0x00000003, 0)  # Error code 3 for invalid command
            client_socket.send(invalid_resp)
            logger.info(f"Sent GENERIC_NACK response: {invalid_resp.hex()}")
        except Exception as e:
            logger.error(f"Error sending GENERIC_NACK: {e}")

    def create_submit_sm_response(self, sequence_number):
        try:
            
            with threading.Lock():
                if not hasattr(self, 'message_id_counter'):
                    self.message_id_counter = 1000000000  # Initial value
                message_id = "001" + str(self.message_id_counter)
                self.message_id_counter += 1
                if self.message_id_counter > 9999999999:
                    self.message_id_counter = 1000000000  # Reset to initial value if max value is exceeded
            message_id_bytes = message_id.encode('ascii') + b'\x00'
            
            
            command_length = 16 + len(message_id_bytes)  # Header + message_id
            response = struct.pack('!IIII', command_length,SUBMIT_SM_RESP,  0, sequence_number) + message_id_bytes
            return response,message_id
        except Exception as e:
            logger.error(f"Error creating SUBMIT_SM response: {e}")
            return b''

    def create_deliver_sm_response(self, sequence_number):
        try:
            message_id = "001" + str(random.randint(1000000000, 9999999999))
            message_id_bytes = message_id.encode('ascii') + b'\x00'
            command_length = 16 + len(message_id_bytes) # Header + message_id
            response = struct.pack('!IIII', command_length, DELIVER_SM_RESP, 0, sequence_number) + message_id_bytes
            return response
        except Exception as e:
            logger.error(f"Error creating DELIVER_SM response: {e}")
            return b''
    def create_nack_response(self, sequence_number):
        try:
            command_length = 16  # Header only
            response = struct.pack('!IIII',  command_length,GENERIC_NACK, 0x0000000F, sequence_number)  # Error code 15 for generic NACK
            return response
        except Exception as e:
            logger.error(f"Error creating NACK response: {e}")
            return b''

    def cleanup(self):
      with self.cleanup_lock:  # Ensure only one thread can execute this block at a time
        logger.info("Server is shutting down...")
        self.shutdown_flag.set()  # Set the shutdown flag
        for client_socket in connected_clients:
            try:
                # Send UNBIND request
                command_length = 16  # Header only, no body for UNBIND
                sequence_number = self.get_next_sequence_number()
                unbind_pdu = struct.pack('!IIII', command_length, UNBIND, 0, sequence_number)
                client_socket.send(unbind_pdu)
                logger.info(f"Sent UNBIND request to client: {client_socket.getpeername()}")

                # Wait for UNBIND_RESP
                # Wait for UNBIND_RESP with a timeout
                client_socket.settimeout(2)  # Set a timeout of 2 seconds
               
                response = self.read_exactly(client_socket, 16)
                if len(response) == 16:
                    _, command_id, _, _ = struct.unpack('!IIII', response)
                    if command_id == UNBIND_RESP:
                        logger.info(f"Received UNBIND_RESP from client: {client_socket.getpeername()}")
                    else:
                        logger.warning(f"Unexpected response received: {response.hex()}")
                else:
                    logger.info(f"Incomplete response received this due to client close connection  : {response.hex()}")
                                        
            except socket.error as e:
                if e.errno == 9:  # Bad file descriptor
                    logger.info(f"Client connection already closed")
                else:
                    logger.error(f"Socket error during unbind process: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during unbind process: {e}")
            finally:
                logger.info("close client socket.")
                client_socket.close()
                if client_socket in connected_clients:
                    connected_clients.remove(client_socket)  # Remove client from the list
        logger.info("All clients unbound. Server shutdown completed.")
        sys.exit("Server shutdown gracefully via Ctrl+C")
        
        

if __name__ == "__main__":
    
    signal.signal(signal.SIGINT, lambda sig, frame: server.cleanup())
    server = SMPPServer(host='0.0.0.0', port=50000)
    server.start()

