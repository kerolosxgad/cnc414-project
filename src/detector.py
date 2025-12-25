from typing import Dict, List, Any, Set
import logging
import os
import re


class ThreatDetector:
    """
    Forensic threat detection engine.
    
    This class analyzes network activity to identify potential
    security incidents and indicators of compromise.
    """
    
    def __init__(self, analysis_results: Dict[str, Any], safe_domains_file: str = None):
        """
        Initialize the threat detector.
        
        Args:
            analysis_results (dict): Results from network analysis
            safe_domains_file (str): Path to file containing known safe domains
        """
        self.analysis_results = analysis_results
        self.logger = logging.getLogger(__name__)
        self.safe_domains = self._load_safe_domains(safe_domains_file)
        self.findings = []
    
    def _load_safe_domains(self, safe_domains_file: str) -> Set[str]:
        """
        Load the list of known safe/trusted domains.
        
        Args:
            safe_domains_file (str): Path to safe domains file
            
        Returns:
            set: Set of safe domain names
        """
        safe_domains = set()
        
        if safe_domains_file and os.path.exists(safe_domains_file):
            try:
                with open(safe_domains_file, 'r') as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith('#'):
                            safe_domains.add(domain.lower())
                self.logger.info(f"Loaded {len(safe_domains)} safe domains")
            except Exception as e:
                self.logger.error(f"Error loading safe domains: {str(e)}")
        else:
            # Default safe domains if file not provided
            safe_domains = {
                'google.com', 'www.google.com', 'googleapis.com',
                'microsoft.com', 'windows.com', 'msftconnecttest.com',
                'apple.com', 'icloud.com', 'mzstatic.com',
                'amazon.com', 'amazonaws.com', 'cloudfront.net',
                'facebook.com', 'fbcdn.net',
                'twitter.com', 'twimg.com',
                'cloudflare.com', 'cdnjs.cloudflare.com',
                'github.com', 'githubusercontent.com',
                'linkedin.com', 'licdn.com'
            }
            self.logger.info(f"Using default safe domains list ({len(safe_domains)} domains)")
        
        return safe_domains
    
    def detect_unknown_domains(self) -> List[Dict[str, Any]]:
        """
        Detect DNS queries to unknown or uncommon domains.
        
        Returns:
            list: List of findings for unknown domains
        """
        findings = []
        dns_analysis = self.analysis_results.get('dns_analysis', {})
        query_frequencies = dns_analysis.get('query_frequencies', {})
        
        for domain, count in query_frequencies.items():
            domain_lower = domain.lower()
            
            # Check if domain is not in safe list
            is_unknown = True
            for safe_domain in self.safe_domains:
                if safe_domain in domain_lower or domain_lower.endswith('.' + safe_domain):
                    is_unknown = False
                    break
            
            if is_unknown:
                severity = 'HIGH' if count > 10 else 'MEDIUM'
                
                finding = {
                    'type': 'UNKNOWN_DOMAIN',
                    'severity': severity,
                    'domain': domain,
                    'query_count': count,
                    'description': f"DNS queries to unknown/uncommon domain: {domain}",
                    'recommendation': "Investigate domain reputation and purpose. Check if domain is associated with phishing or malware campaigns."
                }
                findings.append(finding)
        
        self.logger.info(f"Detected {len(findings)} unknown domains")
        return findings
    
    def detect_excessive_dns_queries(self, threshold: int = 20) -> List[Dict[str, Any]]:
        """
        Detect excessive DNS queries to same domain (potential DNS tunneling).
        
        Args:
            threshold (int): Number of queries to consider excessive
            
        Returns:
            list: List of findings for excessive DNS queries
        """
        findings = []
        dns_analysis = self.analysis_results.get('dns_analysis', {})
        excessive_queries = dns_analysis.get('excessive_queries', {})
        
        for domain, count in excessive_queries.items():
            if count >= threshold:
                finding = {
                    'type': 'EXCESSIVE_DNS_QUERIES',
                    'severity': 'HIGH',
                    'domain': domain,
                    'query_count': count,
                    'description': f"Excessive DNS queries detected: {count} queries to {domain}",
                    'recommendation': "Investigate for DNS tunneling or data exfiltration via DNS. Analyze query patterns and payload sizes."
                }
                findings.append(finding)
        
        self.logger.info(f"Detected {len(findings)} instances of excessive DNS queries")
        return findings
    
    def detect_large_data_transfers(self, threshold_mb: float = 10.0) -> List[Dict[str, Any]]:
        """
        Detect large outbound data transfers (potential data exfiltration).
        
        Args:
            threshold_mb (float): Data transfer threshold in megabytes
            
        Returns:
            list: List of findings for large data transfers
        """
        findings = []
        ip_analysis = self.analysis_results.get('ip_analysis', {})
        ip_data_stats = ip_analysis.get('ip_data_stats', {})
        private_ips = ip_analysis.get('private_ips', [])
        
        threshold_bytes = threshold_mb * 1024 * 1024
        
        for ip, stats in ip_data_stats.items():
            # Focus on outbound traffic from private IPs
            if ip in private_ips and stats['sent_bytes'] > threshold_bytes:
                finding = {
                    'type': 'LARGE_DATA_TRANSFER',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'bytes_sent': stats['sent_bytes'],
                    'megabytes_sent': stats['sent_mb'],
                    'description': f"Large outbound data transfer detected from {ip}: {stats['sent_mb']} MB",
                    'recommendation': "Investigate what data was transmitted. Check if this matches legitimate business activity or represents potential data exfiltration."
                }
                findings.append(finding)
        
        self.logger.info(f"Detected {len(findings)} large data transfers")
        return findings
    
    def detect_suspicious_ip_patterns(self) -> List[Dict[str, Any]]:
        """
        Detect suspicious IP communication patterns (private to unknown public).
        
        Returns:
            list: List of findings for suspicious IP patterns
        """
        findings = []
        ip_analysis = self.analysis_results.get('ip_analysis', {})
        top_communications = ip_analysis.get('top_communications', [])
        private_ips = set(ip_analysis.get('private_ips', []))
        
        # Known safe public IP ranges (CDNs, major cloud providers - simplified)
        # In production, this would be more comprehensive
        known_safe_patterns = [
            r'^8\.8\.',      # Google DNS
            r'^1\.1\.',      # Cloudflare DNS
            r'^52\.',        # AWS
            r'^54\.',        # AWS
            r'^13\.',        # AWS
            r'^104\.',       # Cloudflare
            r'^172\.217\.',  # Google
        ]
        
        for comm_pair, packet_count in top_communications:
            try:
                # Parse communication pair
                src_dst = comm_pair.split(' -> ')
                if len(src_dst) == 2:
                    src_ip = src_dst[0]
                    dst_ip = src_dst[1]
                    
                    # Check if private IP communicating with public IP
                    if src_ip in private_ips and dst_ip not in private_ips:
                        # Check if destination is not in known safe patterns
                        is_known_safe = False
                        for pattern in known_safe_patterns:
                            if re.match(pattern, dst_ip):
                                is_known_safe = True
                                break
                        
                        if not is_known_safe and packet_count > 50:
                            finding = {
                                'type': 'SUSPICIOUS_IP_COMMUNICATION',
                                'severity': 'MEDIUM',
                                'source_ip': src_ip,
                                'destination_ip': dst_ip,
                                'packet_count': packet_count,
                                'description': f"Suspicious communication pattern: {src_ip} -> {dst_ip} ({packet_count} packets)",
                                'recommendation': "Investigate the destination IP address. Check if it's associated with known malicious activity or command-and-control servers."
                            }
                            findings.append(finding)
            except Exception as e:
                self.logger.debug(f"Error parsing communication pair: {str(e)}")
        
        self.logger.info(f"Detected {len(findings)} suspicious IP communication patterns")
        return findings
    
    def detect_unusual_ports(self) -> List[Dict[str, Any]]:
        """
        Detect usage of unusual or non-standard ports.
        
        Returns:
            list: List of findings for unusual port usage
        """
        findings = []
        tcp_analysis = self.analysis_results.get('tcp_analysis', {})
        unusual_ports = tcp_analysis.get('unusual_ports', {})
        
        # High-risk port threshold
        high_risk_threshold = 100
        
        for port_info, count in unusual_ports.items():
            if count > 10:  # Only report if used multiple times
                severity = 'HIGH' if count > high_risk_threshold else 'MEDIUM'
                
                finding = {
                    'type': 'UNUSUAL_PORT',
                    'severity': severity,
                    'port_info': port_info,
                    'usage_count': count,
                    'description': f"Unusual port usage detected: {port_info} ({count} occurrences)",
                    'recommendation': "Investigate the service running on this port. Verify if it's legitimate business traffic or potential backdoor/tunnel."
                }
                findings.append(finding)
        
        self.logger.info(f"Detected {len(findings)} unusual port usages")
        return findings
    
    def detect_http_post_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect suspicious HTTP POST requests (potential data exfiltration).
        
        Returns:
            list: List of findings for HTTP POST anomalies
        """
        findings = []
        http_analysis = self.analysis_results.get('http_analysis', {})
        post_requests = http_analysis.get('post_requests', [])
        
        # Group POST requests by host
        posts_by_host = {}
        for req in post_requests:
            host = req['host']
            if host not in posts_by_host:
                posts_by_host[host] = []
            posts_by_host[host].append(req)
        
        # Check for excessive POST requests to same host
        for host, requests in posts_by_host.items():
            if len(requests) > 5:
                # Check if host is in safe list
                host_lower = host.lower()
                is_safe = any(safe_domain in host_lower for safe_domain in self.safe_domains)
                
                if not is_safe:
                    finding = {
                        'type': 'SUSPICIOUS_HTTP_POST',
                        'severity': 'HIGH',
                        'host': host,
                        'post_count': len(requests),
                        'urls': list(set([r['url'] for r in requests])),
                        'description': f"Multiple HTTP POST requests to unknown host: {host} ({len(requests)} requests)",
                        'recommendation': "Investigate POST request payloads. May indicate data exfiltration via HTTP."
                    }
                    findings.append(finding)
        
        self.logger.info(f"Detected {len(findings)} HTTP POST anomalies")
        return findings
    
    def detect_potential_phishing_indicators(self) -> List[Dict[str, Any]]:
        """
        Detect potential phishing indicators in domains and URLs.
        
        Returns:
            list: List of findings for potential phishing indicators
        """
        findings = []
        
        # Check DNS queries for phishing patterns
        dns_analysis = self.analysis_results.get('dns_analysis', {})
        query_frequencies = dns_analysis.get('query_frequencies', {})
        
        # Common phishing indicators
        phishing_keywords = [
            'login', 'secure', 'account', 'verify', 'update', 'confirm',
            'banking', 'paypal', 'apple-id', 'microsoft-account', 'signin'
        ]
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        
        for domain, count in query_frequencies.items():
            domain_lower = domain.lower()
            
            # Check for suspicious TLDs
            has_suspicious_tld = any(domain_lower.endswith(tld) for tld in suspicious_tlds)
            
            # Check for phishing keywords in domain
            has_phishing_keyword = any(keyword in domain_lower for keyword in phishing_keywords)
            
            # Check for typosquatting patterns (multiple hyphens, mixed case weirdness)
            has_multiple_hyphens = domain.count('-') > 2
            
            if (has_suspicious_tld or (has_phishing_keyword and has_multiple_hyphens)):
                finding = {
                    'type': 'POTENTIAL_PHISHING',
                    'severity': 'HIGH',
                    'domain': domain,
                    'query_count': count,
                    'indicators': [],
                    'description': f"Potential phishing domain detected: {domain}",
                    'recommendation': "Investigate domain for phishing campaign. Check domain reputation and WHOIS information."
                }
                
                if has_suspicious_tld:
                    finding['indicators'].append('Suspicious TLD')
                if has_phishing_keyword:
                    finding['indicators'].append('Contains phishing keywords')
                if has_multiple_hyphens:
                    finding['indicators'].append('Multiple hyphens (typosquatting pattern)')
                
                findings.append(finding)
        
        # Check HTTP URLs for phishing patterns
        http_analysis = self.analysis_results.get('http_analysis', {})
        all_urls = http_analysis.get('all_urls', [])
        
        for url in all_urls:
            url_lower = url.lower()
            
            # Check for phishing patterns in URL path
            if any(keyword in url_lower for keyword in phishing_keywords):
                # Check if it's not a known safe domain
                is_safe = any(safe_domain in url_lower for safe_domain in self.safe_domains)
                
                if not is_safe:
                    finding = {
                        'type': 'SUSPICIOUS_URL',
                        'severity': 'MEDIUM',
                        'url': url,
                        'description': f"Suspicious URL pattern detected: {url}",
                        'recommendation': "Investigate URL for phishing content. Check if site is impersonating legitimate service."
                    }
                    findings.append(finding)
        
        self.logger.info(f"Detected {len(findings)} potential phishing indicators")
        return findings
    
    def run_all_detections(self) -> Dict[str, Any]:
        """
        Execute all detection algorithms and compile findings.
        
        Returns:
            dict: All detection findings organized by type
        """
        self.logger.info("Starting threat detection analysis...")
        
        all_findings = []
        
        # Run all detection algorithms
        all_findings.extend(self.detect_unknown_domains())
        all_findings.extend(self.detect_excessive_dns_queries())
        all_findings.extend(self.detect_large_data_transfers())
        all_findings.extend(self.detect_suspicious_ip_patterns())
        all_findings.extend(self.detect_unusual_ports())
        all_findings.extend(self.detect_http_post_anomalies())
        all_findings.extend(self.detect_potential_phishing_indicators())
        
        # Organize findings by severity
        findings_by_severity = {
            'HIGH': [f for f in all_findings if f['severity'] == 'HIGH'],
            'MEDIUM': [f for f in all_findings if f['severity'] == 'MEDIUM'],
            'LOW': [f for f in all_findings if f.get('severity') == 'LOW']
        }
        
        # Organize findings by type
        findings_by_type = {}
        for finding in all_findings:
            finding_type = finding['type']
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)
        
        self.findings = all_findings
        
        results = {
            'all_findings': all_findings,
            'findings_by_severity': findings_by_severity,
            'findings_by_type': findings_by_type,
            'total_findings': len(all_findings),
            'high_severity_count': len(findings_by_severity['HIGH']),
            'medium_severity_count': len(findings_by_severity['MEDIUM']),
            'low_severity_count': len(findings_by_severity['LOW'])
        }
        
        self.logger.info(f"Detection complete: {len(all_findings)} findings identified")
        self.logger.info(f"Severity breakdown - HIGH: {results['high_severity_count']}, "
                        f"MEDIUM: {results['medium_severity_count']}, "
                        f"LOW: {results['low_severity_count']}")
        
        return results
    
    def get_indicators_of_compromise(self) -> List[str]:
        """
        Extract indicators of compromise (IOCs) from findings.
        
        Returns:
            list: List of IOC strings
        """
        iocs = []
        
        for finding in self.findings:
            if finding['type'] == 'UNKNOWN_DOMAIN':
                iocs.append(f"Domain: {finding['domain']}")
            elif finding['type'] == 'SUSPICIOUS_IP_COMMUNICATION':
                iocs.append(f"IP: {finding['destination_ip']}")
            elif finding['type'] == 'POTENTIAL_PHISHING':
                iocs.append(f"Phishing Domain: {finding['domain']}")
            elif finding['type'] == 'SUSPICIOUS_URL':
                iocs.append(f"URL: {finding['url']}")
        
        return list(set(iocs))  # Remove duplicates


if __name__ == "__main__":
    print("Threat Detector Module - Network Packet Investigator")
    print("=" * 60)
    print("This module is designed to be imported and used by the main application.")
