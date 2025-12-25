from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, ICMP
from scapy.layers.http import HTTPRequest, HTTP
import logging
from typing import List, Dict, Any, Optional
import os


class PCAPParser:
    """
    PCAP file parser for forensic analysis.
    
    This class provides methods to load and parse PCAP files,
    extracting relevant network packet information for investigation.
    """
    
    def __init__(self, pcap_file: str):
        """
        Initialize the PCAP parser.
        
        Args:
            pcap_file (str): Path to the PCAP file to analyze
        """
        self.pcap_file = pcap_file
        self.packets = []
        self.total_packets = 0
        self.logger = logging.getLogger(__name__)
        
    def load_pcap(self, progress_callback=None) -> bool:
        """
        Load and parse the PCAP file.
        
        Args:
            progress_callback: Optional callback function for progress updates
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not os.path.exists(self.pcap_file):
                self.logger.error(f"PCAP file not found: {self.pcap_file}")
                return False
            
            self.logger.info(f"Loading PCAP file: {self.pcap_file}")
            
            # Load packets from PCAP file
            self.packets = rdpcap(self.pcap_file)
            self.total_packets = len(self.packets)
            
            self.logger.info(f"Successfully loaded {self.total_packets} packets")
            
            if progress_callback:
                progress_callback(100, f"Loaded {self.total_packets} packets")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading PCAP file: {str(e)}")
            return False
    
    def extract_packet_info(self, progress_callback=None) -> Dict[str, Any]:
        """
        Extract detailed information from all packets.
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            dict: Dictionary containing extracted packet information
        """
        packet_info = {
            'dns_queries': [],
            'http_requests': [],
            'tcp_sessions': [],
            'udp_sessions': [],
            'protocol_counts': {
                'TCP': 0,
                'UDP': 0,
                'ICMP': 0,
                'DNS': 0,
                'HTTP': 0,
                'Other': 0
            },
            'ip_communications': {},
            'port_usage': {},
            'data_volumes': {}
        }
        
        try:
            for i, packet in enumerate(self.packets):
                # Update progress
                if progress_callback and i % 100 == 0:
                    progress = int((i / self.total_packets) * 100)
                    progress_callback(progress, f"Analyzing packet {i}/{self.total_packets}")
                
                # Extract IP layer information
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Track IP communications
                    comm_key = f"{src_ip} -> {dst_ip}"
                    packet_info['ip_communications'][comm_key] = \
                        packet_info['ip_communications'].get(comm_key, 0) + 1
                    
                    # Track data volumes
                    packet_size = len(packet)
                    if src_ip not in packet_info['data_volumes']:
                        packet_info['data_volumes'][src_ip] = {'sent': 0, 'received': 0}
                    if dst_ip not in packet_info['data_volumes']:
                        packet_info['data_volumes'][dst_ip] = {'sent': 0, 'received': 0}
                    
                    packet_info['data_volumes'][src_ip]['sent'] += packet_size
                    packet_info['data_volumes'][dst_ip]['received'] += packet_size
                
                # Extract DNS queries
                if DNS in packet and packet[DNS].qr == 0:  # DNS query
                    try:
                        query_name = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                        query_name = query_name.rstrip('.')
                        
                        dns_info = {
                            'query': query_name,
                            'src_ip': packet[IP].src if IP in packet else 'Unknown',
                            'dst_ip': packet[IP].dst if IP in packet else 'Unknown',
                            'timestamp': float(packet.time)
                        }
                        packet_info['dns_queries'].append(dns_info)
                        packet_info['protocol_counts']['DNS'] += 1
                    except Exception as e:
                        self.logger.debug(f"Error parsing DNS packet: {str(e)}")
                
                # Extract HTTP requests
                if packet.haslayer(HTTPRequest):
                    try:
                        http_layer = packet[HTTPRequest]
                        
                        http_info = {
                            'method': http_layer.Method.decode() if http_layer.Method else 'Unknown',
                            'host': http_layer.Host.decode() if http_layer.Host else 'Unknown',
                            'path': http_layer.Path.decode() if http_layer.Path else '/',
                            'src_ip': packet[IP].src if IP in packet else 'Unknown',
                            'dst_ip': packet[IP].dst if IP in packet else 'Unknown',
                            'timestamp': float(packet.time)
                        }
                        
                        # Construct full URL
                        http_info['url'] = f"http://{http_info['host']}{http_info['path']}"
                        packet_info['http_requests'].append(http_info)
                        packet_info['protocol_counts']['HTTP'] += 1
                    except Exception as e:
                        self.logger.debug(f"Error parsing HTTP packet: {str(e)}")
                
                # Extract TCP session information
                if TCP in packet:
                    try:
                        tcp_info = {
                            'src_ip': packet[IP].src if IP in packet else 'Unknown',
                            'src_port': packet[TCP].sport,
                            'dst_ip': packet[IP].dst if IP in packet else 'Unknown',
                            'dst_port': packet[TCP].dport,
                            'flags': packet[TCP].flags,
                            'seq': packet[TCP].seq,
                            'payload_size': len(packet[TCP].payload) if packet[TCP].payload else 0,
                            'timestamp': float(packet.time)
                        }
                        packet_info['tcp_sessions'].append(tcp_info)
                        packet_info['protocol_counts']['TCP'] += 1
                        
                        # Track port usage
                        src_port_key = f"{tcp_info['src_ip']}:{tcp_info['src_port']}"
                        dst_port_key = f"{tcp_info['dst_ip']}:{tcp_info['dst_port']}"
                        packet_info['port_usage'][src_port_key] = \
                            packet_info['port_usage'].get(src_port_key, 0) + 1
                        packet_info['port_usage'][dst_port_key] = \
                            packet_info['port_usage'].get(dst_port_key, 0) + 1
                    except Exception as e:
                        self.logger.debug(f"Error parsing TCP packet: {str(e)}")
                
                # Extract UDP session information
                if UDP in packet:
                    try:
                        udp_info = {
                            'src_ip': packet[IP].src if IP in packet else 'Unknown',
                            'src_port': packet[UDP].sport,
                            'dst_ip': packet[IP].dst if IP in packet else 'Unknown',
                            'dst_port': packet[UDP].dport,
                            'payload_size': len(packet[UDP].payload) if packet[UDP].payload else 0,
                            'timestamp': float(packet.time)
                        }
                        packet_info['udp_sessions'].append(udp_info)
                        packet_info['protocol_counts']['UDP'] += 1
                    except Exception as e:
                        self.logger.debug(f"Error parsing UDP packet: {str(e)}")
                
                # Count ICMP packets
                if ICMP in packet:
                    packet_info['protocol_counts']['ICMP'] += 1
                
                # Count other protocols
                if not any([TCP in packet, UDP in packet, ICMP in packet]):
                    if IP in packet:
                        packet_info['protocol_counts']['Other'] += 1
            
            if progress_callback:
                progress_callback(100, "Packet extraction complete")
            
            self.logger.info("Packet extraction completed successfully")
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error extracting packet information: {str(e)}")
            raise
    
    def get_packet_count(self) -> int:
        """Get the total number of packets in the PCAP file."""
        return self.total_packets
    
    def get_packets(self) -> List:
        """Get the raw packet list."""
        return self.packets


def setup_logging(log_level=logging.INFO):
    """Configure logging for the PCAP parser module."""
    import os
    os.makedirs('logs', exist_ok=True)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join('logs', 'forensic_analysis.log')),
            logging.StreamHandler()
        ]
    )


if __name__ == "__main__":
    # Test module independently
    setup_logging()
    print("PCAP Parser Module - Network Packet Investigator")
    print("=" * 60)
    print("This module is designed to be imported and used by the main application.")
    print("For testing, provide a PCAP file path.")
