"""
Network Packet Investigator - Analysis Module

Description:
    This module performs forensic analysis on extracted packet data.
    It aggregates information, computes statistics, and prepares data
    for detection algorithms and visualization.

Author: Digital Forensics Team
Date: December 23, 2025
"""

from collections import Counter, defaultdict
from typing import Dict, List, Any, Tuple
import logging
from datetime import datetime


class NetworkAnalyzer:
    """
    Forensic analysis engine for network packet data.
    
    This class processes extracted packet information to generate
    meaningful insights for forensic investigation.
    """
    
    def __init__(self, packet_info: Dict[str, Any]):
        """
        Initialize the analyzer with packet information.
        
        Args:
            packet_info (dict): Extracted packet information from PCAP parser
        """
        self.packet_info = packet_info
        self.logger = logging.getLogger(__name__)
        self.analysis_results = {}
    
    def analyze_dns_activity(self) -> Dict[str, Any]:
        """
        Analyze DNS query patterns for forensic investigation.
        
        Returns:
            dict: DNS analysis results including query frequencies and patterns
        """
        dns_queries = self.packet_info.get('dns_queries', [])
        
        # Count queries per domain
        domain_counter = Counter([q['query'] for q in dns_queries])
        
        # Group queries by source IP
        queries_by_src = defaultdict(list)
        for query in dns_queries:
            queries_by_src[query['src_ip']].append(query['query'])
        
        # Calculate query statistics
        total_queries = len(dns_queries)
        unique_domains = len(domain_counter)
        
        # Find top queried domains
        top_domains = domain_counter.most_common(20)
        
        # Calculate query frequency metrics
        query_frequencies = {
            domain: count for domain, count in domain_counter.items()
        }
        
        # Identify domains with excessive queries (potential DNS tunneling)
        excessive_threshold = 10
        excessive_queries = {
            domain: count for domain, count in domain_counter.items()
            if count > excessive_threshold
        }
        
        # Analyze query patterns by source
        src_query_patterns = {}
        for src_ip, queries in queries_by_src.items():
            src_query_patterns[src_ip] = {
                'total_queries': len(queries),
                'unique_domains': len(set(queries)),
                'top_domains': Counter(queries).most_common(5)
            }
        
        analysis = {
            'total_queries': total_queries,
            'unique_domains': unique_domains,
            'top_domains': top_domains,
            'query_frequencies': query_frequencies,
            'excessive_queries': excessive_queries,
            'queries_by_source': src_query_patterns,
            'raw_queries': dns_queries
        }
        
        self.logger.info(f"DNS Analysis: {total_queries} queries, {unique_domains} unique domains")
        return analysis
    
    def analyze_http_activity(self) -> Dict[str, Any]:
        """
        Analyze HTTP requests for suspicious patterns.
        
        Returns:
            dict: HTTP analysis results including URLs, methods, and hosts
        """
        http_requests = self.packet_info.get('http_requests', [])
        
        # Count requests by host
        host_counter = Counter([req['host'] for req in http_requests])
        
        # Count requests by method
        method_counter = Counter([req['method'] for req in http_requests])
        
        # Group by source IP
        requests_by_src = defaultdict(list)
        for req in http_requests:
            requests_by_src[req['src_ip']].append(req)
        
        # Identify POST requests (potential data exfiltration)
        post_requests = [req for req in http_requests if req['method'] == 'POST']
        
        # Extract all unique URLs
        unique_urls = list(set([req['url'] for req in http_requests]))
        
        # Top requested hosts
        top_hosts = host_counter.most_common(20)
        
        # Analyze request patterns by source
        src_request_patterns = {}
        for src_ip, requests in requests_by_src.items():
            src_request_patterns[src_ip] = {
                'total_requests': len(requests),
                'unique_hosts': len(set([r['host'] for r in requests])),
                'methods': Counter([r['method'] for r in requests]),
                'post_requests': len([r for r in requests if r['method'] == 'POST'])
            }
        
        analysis = {
            'total_requests': len(http_requests),
            'unique_urls': len(unique_urls),
            'unique_hosts': len(host_counter),
            'top_hosts': top_hosts,
            'method_distribution': dict(method_counter),
            'post_requests': post_requests,
            'requests_by_source': src_request_patterns,
            'all_urls': unique_urls,
            'raw_requests': http_requests
        }
        
        self.logger.info(f"HTTP Analysis: {len(http_requests)} requests, {len(unique_urls)} unique URLs")
        return analysis
    
    def analyze_tcp_sessions(self) -> Dict[str, Any]:
        """
        Analyze TCP sessions for connection patterns and data transfer.
        
        Returns:
            dict: TCP session analysis including connections and data volumes
        """
        tcp_sessions = self.packet_info.get('tcp_sessions', [])
        
        # Group sessions by connection (src_ip:src_port -> dst_ip:dst_port)
        connections = defaultdict(list)
        for session in tcp_sessions:
            conn_key = f"{session['src_ip']}:{session['src_port']} -> {session['dst_ip']}:{session['dst_port']}"
            connections[conn_key].append(session)
        
        # Calculate data transfer per connection
        connection_stats = {}
        for conn_key, packets in connections.items():
            total_payload = sum([p['payload_size'] for p in packets])
            connection_stats[conn_key] = {
                'packet_count': len(packets),
                'total_bytes': total_payload,
                'flags_seen': list(set([str(p['flags']) for p in packets]))
            }
        
        # Identify top connections by data volume
        top_connections = sorted(
            connection_stats.items(),
            key=lambda x: x[1]['total_bytes'],
            reverse=True
        )[:20]
        
        # Analyze port usage
        src_ports = Counter([s['src_port'] for s in tcp_sessions])
        dst_ports = Counter([s['dst_port'] for s in tcp_sessions])
        
        # Identify unusual ports (not in common list)
        common_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080}
        unusual_dst_ports = {port: count for port, count in dst_ports.items() 
                             if port not in common_ports}
        
        # Calculate total data transfer
        total_data_transferred = sum([conn['total_bytes'] for conn in connection_stats.values()])
        
        analysis = {
            'total_sessions': len(tcp_sessions),
            'unique_connections': len(connections),
            'connection_stats': connection_stats,
            'top_connections': top_connections,
            'src_port_distribution': dict(src_ports.most_common(20)),
            'dst_port_distribution': dict(dst_ports.most_common(20)),
            'unusual_ports': unusual_dst_ports,
            'total_data_transferred': total_data_transferred,
            'raw_sessions': tcp_sessions
        }
        
        self.logger.info(f"TCP Analysis: {len(tcp_sessions)} sessions, {len(connections)} unique connections")
        return analysis
    
    def analyze_protocol_distribution(self) -> Dict[str, Any]:
        """
        Analyze the distribution of network protocols.
        
        Returns:
            dict: Protocol statistics and distribution
        """
        protocol_counts = self.packet_info.get('protocol_counts', {})
        
        total_packets = sum(protocol_counts.values())
        
        # Calculate percentages
        protocol_percentages = {}
        for protocol, count in protocol_counts.items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            protocol_percentages[protocol] = {
                'count': count,
                'percentage': round(percentage, 2)
            }
        
        analysis = {
            'total_packets': total_packets,
            'protocol_counts': protocol_counts,
            'protocol_percentages': protocol_percentages
        }
        
        self.logger.info(f"Protocol Analysis: {total_packets} total packets")
        return analysis
    
    def analyze_ip_communications(self) -> Dict[str, Any]:
        """
        Analyze IP-to-IP communication patterns.
        
        Returns:
            dict: IP communication statistics and patterns
        """
        ip_communications = self.packet_info.get('ip_communications', {})
        data_volumes = self.packet_info.get('data_volumes', {})
        
        # Find most active communication pairs
        top_communications = sorted(
            ip_communications.items(),
            key=lambda x: x[1],
            reverse=True
        )[:20]
        
        # Analyze data volumes per IP
        ip_data_stats = {}
        for ip, volumes in data_volumes.items():
            ip_data_stats[ip] = {
                'sent_bytes': volumes['sent'],
                'received_bytes': volumes['received'],
                'total_bytes': volumes['sent'] + volumes['received'],
                'sent_mb': round(volumes['sent'] / (1024 * 1024), 2),
                'received_mb': round(volumes['received'] / (1024 * 1024), 2)
            }
        
        # Find top senders and receivers
        top_senders = sorted(
            ip_data_stats.items(),
            key=lambda x: x[1]['sent_bytes'],
            reverse=True
        )[:10]
        
        top_receivers = sorted(
            ip_data_stats.items(),
            key=lambda x: x[1]['received_bytes'],
            reverse=True
        )[:10]
        
        # Identify private and public IPs
        private_ips = []
        public_ips = []
        for ip in ip_data_stats.keys():
            if self._is_private_ip(ip):
                private_ips.append(ip)
            else:
                public_ips.append(ip)
        
        analysis = {
            'total_communications': len(ip_communications),
            'top_communications': top_communications,
            'ip_data_stats': ip_data_stats,
            'top_senders': top_senders,
            'top_receivers': top_receivers,
            'private_ips': private_ips,
            'public_ips': public_ips
        }
        
        self.logger.info(f"IP Analysis: {len(ip_data_stats)} unique IPs")
        return analysis
    
    def _is_private_ip(self, ip: str) -> bool:
        """
        Check if an IP address is private.
        
        Args:
            ip (str): IP address to check
            
        Returns:
            bool: True if private, False otherwise
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # Private IP ranges
            if first_octet == 10:
                return True
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
            if first_octet == 192 and second_octet == 168:
                return True
            if ip == '127.0.0.1':
                return True
            
            return False
        except:
            return False
    
    def run_full_analysis(self) -> Dict[str, Any]:
        """
        Execute complete forensic analysis on all packet data.
        
        Returns:
            dict: Complete analysis results
        """
        self.logger.info("Starting full forensic analysis...")
        
        results = {
            'dns_analysis': self.analyze_dns_activity(),
            'http_analysis': self.analyze_http_activity(),
            'tcp_analysis': self.analyze_tcp_sessions(),
            'protocol_analysis': self.analyze_protocol_distribution(),
            'ip_analysis': self.analyze_ip_communications()
        }
        
        self.analysis_results = results
        self.logger.info("Full forensic analysis completed")
        
        return results
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """
        Generate summary statistics for the analysis.
        
        Returns:
            dict: Summary statistics
        """
        if not self.analysis_results:
            self.run_full_analysis()
        
        summary = {
            'total_dns_queries': self.analysis_results['dns_analysis']['total_queries'],
            'unique_domains': self.analysis_results['dns_analysis']['unique_domains'],
            'total_http_requests': self.analysis_results['http_analysis']['total_requests'],
            'unique_urls': self.analysis_results['http_analysis']['unique_urls'],
            'total_tcp_sessions': self.analysis_results['tcp_analysis']['total_sessions'],
            'total_data_transferred_bytes': self.analysis_results['tcp_analysis']['total_data_transferred'],
            'total_packets': self.analysis_results['protocol_analysis']['total_packets'],
            'protocol_distribution': self.analysis_results['protocol_analysis']['protocol_counts']
        }
        
        return summary


if __name__ == "__main__":
    print("Network Analyzer Module - Network Packet Investigator")
    print("=" * 60)
    print("This module is designed to be imported and used by the main application.")
