import csv
import os
from datetime import datetime
from typing import Dict, List, Any
import logging

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    import matplotlib.pyplot as plt
    from io import BytesIO
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


class ForensicReporter:
    """
    Forensic report generation engine.
    
    This class creates detailed forensic reports in multiple formats
    documenting analysis results and findings.
    """
    
    def __init__(self, analysis_results: Dict[str, Any], detection_results: Dict[str, Any],
                 case_name: str = "Network Forensic Investigation",
                 analyst_name: str = "Digital Forensics Team"):
        """
        Initialize the forensic reporter.
        
        Args:
            analysis_results (dict): Results from network analysis
            detection_results (dict): Results from threat detection
            case_name (str): Name of the forensic case
            analyst_name (str): Name of the analyst/team
        """
        self.analysis_results = analysis_results
        self.detection_results = detection_results
        self.case_name = case_name
        self.analyst_name = analyst_name
        self.logger = logging.getLogger(__name__)
        self.report_timestamp = datetime.now()
    
    def generate_txt_report(self, output_path: str) -> bool:
        """
        Generate a comprehensive TXT forensic report.
        
        Args:
            output_path (str): Path where the report will be saved
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("FORENSIC ANALYSIS REPORT\n")
                f.write("Network Packet Investigator - Digital Forensics Tool\n")
                f.write("=" * 80 + "\n\n")
                
                # Case Information
                f.write("CASE INFORMATION\n")
                f.write("-" * 80 + "\n")
                f.write(f"Case Name: {self.case_name}\n")
                f.write(f"Analyst: {self.analyst_name}\n")
                f.write(f"Report Generated: {self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Tool Version: 1.0.0\n")
                f.write("\n")
                
                # Case Description
                f.write("CASE DESCRIPTION\n")
                f.write("-" * 80 + "\n")
                f.write("This forensic analysis examines network traffic patterns to identify\n")
                f.write("indicators of compromise and suspicious activities in the captured\n")
                f.write("network data.\n")
                f.write("\n\n")
                
                # Executive Summary
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 80 + "\n")
                summary = self._generate_executive_summary()
                f.write(summary)
                f.write("\n\n")
                
                # Analysis Results
                f.write("DETAILED ANALYSIS RESULTS\n")
                f.write("=" * 80 + "\n\n")
                
                # Protocol Distribution
                self._write_protocol_analysis(f)
                
                # DNS Analysis
                self._write_dns_analysis(f)
                
                # HTTP Analysis
                self._write_http_analysis(f)
                
                # TCP Analysis
                self._write_tcp_analysis(f)
                
                # IP Communication Analysis
                self._write_ip_analysis(f)
                
                # Detection Findings
                f.write("\n")
                f.write("THREAT DETECTION FINDINGS\n")
                f.write("=" * 80 + "\n\n")
                self._write_detection_findings(f)
                
                # Indicators of Compromise
                f.write("\n")
                f.write("INDICATORS OF COMPROMISE (IOCs)\n")
                f.write("-" * 80 + "\n")
                self._write_iocs(f)
                
                # Conclusion
                f.write("\n")
                f.write("ANALYST CONCLUSION\n")
                f.write("-" * 80 + "\n")
                self._write_conclusion(f)
                
                # Footer
                f.write("\n")
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            self.logger.info(f"TXT report generated: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating TXT report: {str(e)}")
            return False
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary text."""
        proto_analysis = self.analysis_results.get('protocol_analysis', {})
        dns_analysis = self.analysis_results.get('dns_analysis', {})
        http_analysis = self.analysis_results.get('http_analysis', {})
        tcp_analysis = self.analysis_results.get('tcp_analysis', {})
        
        findings = self.detection_results.get('all_findings', [])
        high_severity = len([f for f in findings if f['severity'] == 'HIGH'])
        
        summary = f"Analysis of network capture identified {proto_analysis.get('total_packets', 0)} packets\n"
        summary += f"across multiple protocols. The investigation revealed:\n\n"
        summary += f"  - {dns_analysis.get('total_queries', 0)} DNS queries to {dns_analysis.get('unique_domains', 0)} unique domains\n"
        summary += f"  - {http_analysis.get('total_requests', 0)} HTTP requests to {http_analysis.get('unique_hosts', 0)} unique hosts\n"
        summary += f"  - {tcp_analysis.get('unique_connections', 0)} unique TCP connections\n"
        summary += f"  - {tcp_analysis.get('total_data_transferred', 0)} bytes transferred\n\n"
        summary += f"Threat Detection Results:\n"
        summary += f"  - Total Findings: {len(findings)}\n"
        summary += f"  - High Severity: {high_severity}\n"
        summary += f"  - Medium Severity: {len([f for f in findings if f['severity'] == 'MEDIUM'])}\n"
        
        return summary
    
    def _write_protocol_analysis(self, f):
        """Write protocol distribution analysis."""
        proto_analysis = self.analysis_results.get('protocol_analysis', {})
        
        f.write("1. PROTOCOL DISTRIBUTION\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total Packets Analyzed: {proto_analysis.get('total_packets', 0)}\n\n")
        
        percentages = proto_analysis.get('protocol_percentages', {})
        for proto, data in percentages.items():
            f.write(f"  {proto:10s}: {data['count']:6d} packets ({data['percentage']:5.2f}%)\n")
        f.write("\n")
    
    def _write_dns_analysis(self, f):
        """Write DNS analysis section."""
        dns_analysis = self.analysis_results.get('dns_analysis', {})
        
        f.write("2. DNS ACTIVITY ANALYSIS\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total DNS Queries: {dns_analysis.get('total_queries', 0)}\n")
        f.write(f"Unique Domains: {dns_analysis.get('unique_domains', 0)}\n\n")
        
        f.write("Top 10 Queried Domains:\n")
        top_domains = dns_analysis.get('top_domains', [])[:10]
        for i, (domain, count) in enumerate(top_domains, 1):
            f.write(f"  {i:2d}. {domain:50s} ({count:4d} queries)\n")
        f.write("\n")
    
    def _write_http_analysis(self, f):
        """Write HTTP analysis section."""
        http_analysis = self.analysis_results.get('http_analysis', {})
        
        f.write("3. HTTP ACTIVITY ANALYSIS\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total HTTP Requests: {http_analysis.get('total_requests', 0)}\n")
        f.write(f"Unique URLs: {http_analysis.get('unique_urls', 0)}\n")
        f.write(f"Unique Hosts: {http_analysis.get('unique_hosts', 0)}\n\n")
        
        f.write("HTTP Method Distribution:\n")
        methods = http_analysis.get('method_distribution', {})
        for method, count in methods.items():
            f.write(f"  {method:10s}: {count:4d} requests\n")
        f.write("\n")
        
        f.write("Top 10 HTTP Hosts:\n")
        top_hosts = http_analysis.get('top_hosts', [])[:10]
        for i, (host, count) in enumerate(top_hosts, 1):
            f.write(f"  {i:2d}. {host:50s} ({count:4d} requests)\n")
        f.write("\n")
    
    def _write_tcp_analysis(self, f):
        """Write TCP analysis section."""
        tcp_analysis = self.analysis_results.get('tcp_analysis', {})
        
        f.write("4. TCP SESSION ANALYSIS\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total TCP Sessions: {tcp_analysis.get('total_sessions', 0)}\n")
        f.write(f"Unique Connections: {tcp_analysis.get('unique_connections', 0)}\n")
        f.write(f"Total Data Transferred: {tcp_analysis.get('total_data_transferred', 0):,} bytes\n\n")
        
        f.write("Top 10 Connections by Data Volume:\n")
        top_conns = tcp_analysis.get('top_connections', [])[:10]
        for i, (conn, stats) in enumerate(top_conns, 1):
            f.write(f"  {i:2d}. {conn}\n")
            f.write(f"      Bytes: {stats['total_bytes']:,}, Packets: {stats['packet_count']}\n")
        f.write("\n")
    
    def _write_ip_analysis(self, f):
        """Write IP communication analysis."""
        ip_analysis = self.analysis_results.get('ip_analysis', {})
        
        f.write("5. IP COMMUNICATION ANALYSIS\n")
        f.write("-" * 80 + "\n")
        
        top_senders = ip_analysis.get('top_senders', [])[:10]
        f.write("Top 10 Data Senders:\n")
        for i, (ip, stats) in enumerate(top_senders, 1):
            f.write(f"  {i:2d}. {ip:20s} - {stats['sent_mb']:8.2f} MB sent\n")
        f.write("\n")
    
    def _write_detection_findings(self, f):
        """Write threat detection findings."""
        findings_by_severity = self.detection_results.get('findings_by_severity', {})
        
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            findings = findings_by_severity.get(severity, [])
            if findings:
                f.write(f"\n{severity} SEVERITY FINDINGS ({len(findings)})\n")
                f.write("-" * 80 + "\n")
                
                for i, finding in enumerate(findings, 1):
                    f.write(f"\nFinding #{i}: {finding['type']}\n")
                    f.write(f"Description: {finding['description']}\n")
                    
                    # Write additional details based on finding type
                    for key, value in finding.items():
                        if key not in ['type', 'severity', 'description', 'recommendation']:
                            if isinstance(value, list) and len(value) > 10:
                                f.write(f"{key}: {len(value)} items (showing first 10)\n")
                                for item in value[:10]:
                                    f.write(f"  - {item}\n")
                            elif isinstance(value, list):
                                f.write(f"{key}:\n")
                                for item in value:
                                    f.write(f"  - {item}\n")
                            else:
                                f.write(f"{key}: {value}\n")
                    
                    f.write(f"Recommendation: {finding['recommendation']}\n")
    
    def _write_iocs(self, f):
        """Write indicators of compromise."""
        findings = self.detection_results.get('all_findings', [])
        
        iocs = {
            'domains': set(),
            'ips': set(),
            'urls': set()
        }
        
        for finding in findings:
            if 'domain' in finding:
                iocs['domains'].add(finding['domain'])
            if 'destination_ip' in finding:
                iocs['ips'].add(finding['destination_ip'])
            if 'url' in finding:
                iocs['urls'].add(finding['url'])
        
        f.write("\nSuspicious Domains:\n")
        for domain in sorted(iocs['domains'])[:20]:
            f.write(f"  - {domain}\n")
        
        if iocs['ips']:
            f.write("\nSuspicious IP Addresses:\n")
            for ip in sorted(iocs['ips'])[:20]:
                f.write(f"  - {ip}\n")
        
        if iocs['urls']:
            f.write("\nSuspicious URLs:\n")
            for url in sorted(iocs['urls'])[:20]:
                f.write(f"  - {url}\n")
        f.write("\n")
    
    def _write_conclusion(self, f):
        """Write analyst conclusion."""
        findings = self.detection_results.get('all_findings', [])
        high_severity = len([f for f in findings if f['severity'] == 'HIGH'])
        
        conclusion = "Based on the forensic analysis of network traffic, "
        
        if high_severity > 0:
            conclusion += f"this investigation identified {high_severity} high-severity findings "
            conclusion += "indicating potential security incidents. The evidence suggests possible "
            conclusion += "phishing activity and/or data exfiltration attempts.\n\n"
            conclusion += "RECOMMENDATIONS:\n"
            conclusion += "1. Isolate affected systems immediately\n"
            conclusion += "2. Investigate identified indicators of compromise\n"
            conclusion += "3. Review authentication logs for compromised credentials\n"
            conclusion += "4. Conduct malware analysis on affected endpoints\n"
            conclusion += "5. Implement network segmentation and monitoring\n"
            conclusion += "6. Update security policies and user training\n"
        else:
            conclusion += "no high-severity threats were identified. However, "
            conclusion += f"{len(findings)} findings require further investigation to ensure "
            conclusion += "network security.\n\n"
            conclusion += "RECOMMENDATIONS:\n"
            conclusion += "1. Continue monitoring identified domains and IPs\n"
            conclusion += "2. Review and update security policies as needed\n"
            conclusion += "3. Maintain regular security audits\n"
        
        f.write(conclusion)
    
    def export_findings_to_csv(self, output_path: str) -> bool:
        """
        Export detection findings to CSV format.
        
        Args:
            output_path (str): Path where the CSV will be saved
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            findings = self.detection_results.get('all_findings', [])
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if not findings:
                    f.write("No findings to export\n")
                    return True
                
                # Determine all possible fields
                all_fields = set()
                for finding in findings:
                    all_fields.update(finding.keys())
                
                # Remove complex fields
                all_fields = [field for field in all_fields 
                             if field not in ['indicators', 'urls', 'top_domains']]
                
                writer = csv.DictWriter(f, fieldnames=sorted(all_fields), 
                                       extrasaction='ignore')
                writer.writeheader()
                
                for finding in findings:
                    # Simplify complex fields for CSV
                    row = finding.copy()
                    if 'indicators' in row:
                        row['indicators'] = '; '.join(row['indicators'])
                    if 'urls' in row:
                        row['urls'] = '; '.join(row['urls'][:5])  # Limit to 5
                    writer.writerow(row)
            
            self.logger.info(f"CSV report generated: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating CSV report: {str(e)}")
            return False
    
    def export_dns_data_to_csv(self, output_path: str) -> bool:
        """Export DNS query data to CSV."""
        try:
            dns_analysis = self.analysis_results.get('dns_analysis', {})
            queries = dns_analysis.get('raw_queries', [])
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['timestamp', 'query', 'src_ip', 'dst_ip'])
                writer.writeheader()
                writer.writerows(queries)
            
            self.logger.info(f"DNS data exported: {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting DNS data: {str(e)}")
            return False
    
    def export_http_data_to_csv(self, output_path: str) -> bool:
        """Export HTTP request data to CSV."""
        try:
            http_analysis = self.analysis_results.get('http_analysis', {})
            requests = http_analysis.get('raw_requests', [])
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['timestamp', 'method', 'host', 
                                                       'path', 'url', 'src_ip', 'dst_ip'])
                writer.writeheader()
                writer.writerows(requests)
            
            self.logger.info(f"HTTP data exported: {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting HTTP data: {str(e)}")
            return False
    
    def generate_pdf_report(self, output_path: str, case_info: Dict[str, str] = None) -> bool:
        """
        Generate a comprehensive PDF forensic report with charts and detailed analysis.
        
        Args:
            output_path (str): Path where the PDF report will be saved
            case_info (dict): Optional dictionary with case information:
                - case_number: Case/Ticket number
                - investigator: Investigator name
                - date: Investigation date
                - description: Case description
                
        Returns:
            bool: True if successful, False otherwise
        """
        if not PDF_AVAILABLE:
            self.logger.error("PDF generation not available. Install reportlab: pip install reportlab")
            return False
        
        try:
            # Create document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=0.75*inch,
                leftMargin=0.75*inch,
                topMargin=1*inch,
                bottomMargin=0.75*inch
            )
            
            # Container for PDF elements
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#2c3e50'),
                spaceAfter=12,
                spaceBefore=12
            )
            
            subheading_style = ParagraphStyle(
                'CustomSubHeading',
                parent=styles['Heading3'],
                fontSize=12,
                textColor=colors.HexColor('#34495e'),
                spaceAfter=6
            )
            
            # Title
            story.append(Paragraph("FORENSIC ANALYSIS REPORT", title_style))
            story.append(Paragraph("Network Packet Investigator", styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Case Information Section
            story.append(Paragraph("CASE INFORMATION", heading_style))
            
            case_data = []
            if case_info:
                if case_info.get('case_number'):
                    case_data.append(['Case Number:', case_info['case_number']])
                if case_info.get('investigator'):
                    case_data.append(['Investigator:', case_info['investigator']])
                if case_info.get('date'):
                    case_data.append(['Date:', case_info['date']])
            else:
                case_data.append(['Case Name:', self.case_name])
                case_data.append(['Analyst:', self.analyst_name])
                case_data.append(['Report Generated:', self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S')])
            
            case_data.append(['Tool Version:', '1.0.0'])
            
            case_table = Table(case_data, colWidths=[2*inch, 4.5*inch])
            case_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#2c3e50')),
                ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(case_table)
            story.append(Spacer(1, 0.2*inch))
            
            # Case Description
            if case_info and case_info.get('description'):
                story.append(Paragraph("Case Description", subheading_style))
                story.append(Paragraph(case_info['description'], styles['Normal']))
            else:
                story.append(Paragraph("Case Description", subheading_style))
                story.append(Paragraph(
                    "This forensic analysis examines network traffic patterns to identify "
                    "indicators of compromise and suspicious activities in the captured network data.",
                    styles['Normal']
                ))
            story.append(Spacer(1, 0.3*inch))
            
            # Executive Summary
            story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
            summary_text = self._generate_pdf_summary()
            story.append(Paragraph(summary_text, styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # Protocol Distribution Chart
            story.append(PageBreak())
            story.append(Paragraph("PROTOCOL ANALYSIS", heading_style))
            
            protocol_chart = self._create_protocol_chart()
            if protocol_chart:
                story.append(protocol_chart)
                story.append(Spacer(1, 0.2*inch))
            
            # Protocol Statistics Table
            proto_analysis = self.analysis_results.get('protocol_analysis', {})
            proto_data = [['Protocol', 'Packet Count', 'Percentage']]
            percentages = proto_analysis.get('protocol_percentages', {})
            for proto, data in percentages.items():
                proto_data.append([proto, f"{data['count']:,}", f"{data['percentage']:.2f}%"])
            
            proto_table = Table(proto_data, colWidths=[2*inch, 2*inch, 2*inch])
            proto_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(proto_table)
            story.append(Spacer(1, 0.3*inch))
            
            # DNS Analysis
            story.append(Paragraph("DNS ACTIVITY ANALYSIS", heading_style))
            dns_analysis = self.analysis_results.get('dns_analysis', {})
            
            dns_summary = f"""
            Total DNS Queries: {dns_analysis.get('total_queries', 0):,}<br/>
            Unique Domains: {dns_analysis.get('unique_domains', 0):,}<br/>
            Domains with Excessive Queries: {len(dns_analysis.get('excessive_queries', {}))}
            """
            story.append(Paragraph(dns_summary, styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            # Top DNS Queries
            story.append(Paragraph("Top 10 Queried Domains", subheading_style))
            top_domains = dns_analysis.get('top_domains', [])[:10]
            if top_domains:
                dns_data = [['Rank', 'Domain', 'Query Count']]
                for i, (domain, count) in enumerate(top_domains, 1):
                    dns_data.append([str(i), domain[:50], str(count)])
                
                dns_table = Table(dns_data, colWidths=[0.6*inch, 4*inch, 1.4*inch])
                dns_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#27ae60')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                    ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ]))
                story.append(dns_table)
            story.append(Spacer(1, 0.3*inch))
            
            # HTTP Analysis
            story.append(PageBreak())
            story.append(Paragraph("HTTP ACTIVITY ANALYSIS", heading_style))
            http_analysis = self.analysis_results.get('http_analysis', {})
            
            http_summary = f"""
            Total HTTP Requests: {http_analysis.get('total_requests', 0):,}<br/>
            Unique URLs: {http_analysis.get('unique_urls', 0):,}<br/>
            Unique Hosts: {http_analysis.get('unique_hosts', 0):,}<br/>
            POST Requests: {len(http_analysis.get('post_requests', []))}
            """
            story.append(Paragraph(http_summary, styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            # Method Distribution
            methods = http_analysis.get('method_distribution', {})
            if methods:
                story.append(Paragraph("HTTP Method Distribution", subheading_style))
                method_data = [['Method', 'Count']]
                for method, count in methods.items():
                    method_data.append([method, str(count)])
                
                method_table = Table(method_data, colWidths=[2*inch, 2*inch])
                method_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e67e22')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ]))
                story.append(method_table)
            story.append(Spacer(1, 0.3*inch))
            
            # TCP Analysis
            story.append(Paragraph("TCP SESSION ANALYSIS", heading_style))
            tcp_analysis = self.analysis_results.get('tcp_analysis', {})
            
            tcp_summary = f"""
            Total TCP Sessions: {tcp_analysis.get('total_sessions', 0):,}<br/>
            Unique Connections: {tcp_analysis.get('unique_connections', 0):,}<br/>
            Total Data Transferred: {tcp_analysis.get('total_data_transferred', 0):,} bytes 
            ({tcp_analysis.get('total_data_transferred', 0) / (1024*1024):.2f} MB)
            """
            story.append(Paragraph(tcp_summary, styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Security Findings
            story.append(PageBreak())
            story.append(Paragraph("SECURITY FINDINGS", heading_style))
            
            findings_by_sev = self.detection_results.get('findings_by_severity', {})
            
            # Findings Summary
            findings_summary = f"""
            <b>Total Findings:</b> {self.detection_results.get('total_findings', 0)}<br/>
            <b><font color="red">High Severity:</font></b> {self.detection_results.get('high_severity_count', 0)}<br/>
            <b><font color="orange">Medium Severity:</font></b> {self.detection_results.get('medium_severity_count', 0)}<br/>
            <b><font color="blue">Low Severity:</font></b> {self.detection_results.get('low_severity_count', 0)}
            """
            story.append(Paragraph(findings_summary, styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # High Severity Findings
            high_findings = findings_by_sev.get('HIGH', [])
            if high_findings:
                story.append(Paragraph("HIGH SEVERITY FINDINGS", subheading_style))
                for i, finding in enumerate(high_findings[:10], 1):  # Limit to 10
                    finding_text = f"""
                    <b>Finding #{i}: {finding['type']}</b><br/>
                    <i>Description:</i> {finding['description']}<br/>
                    <i>Recommendation:</i> {finding['recommendation']}
                    """
                    story.append(Paragraph(finding_text, styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
            
            # Medium Severity Findings
            medium_findings = findings_by_sev.get('MEDIUM', [])
            if medium_findings:
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph("MEDIUM SEVERITY FINDINGS", subheading_style))
                for i, finding in enumerate(medium_findings[:5], 1):  # Limit to 5
                    finding_text = f"""
                    <b>Finding #{i}: {finding['type']}</b><br/>
                    <i>Description:</i> {finding['description']}
                    """
                    story.append(Paragraph(finding_text, styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
            
            # IOCs
            story.append(PageBreak())
            story.append(Paragraph("INDICATORS OF COMPROMISE", heading_style))
            
            iocs = self._extract_iocs_for_pdf()
            
            if iocs['domains']:
                story.append(Paragraph("Suspicious Domains", subheading_style))
                domain_list = "<br/>".join([f"• {d}" for d in list(iocs['domains'])[:20]])
                story.append(Paragraph(domain_list, styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            if iocs['ips']:
                story.append(Paragraph("Suspicious IP Addresses", subheading_style))
                ip_list = "<br/>".join([f"• {ip}" for ip in list(iocs['ips'])[:20]])
                story.append(Paragraph(ip_list, styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            if iocs['urls']:
                story.append(Paragraph("Suspicious URLs", subheading_style))
                url_list = "<br/>".join([f"• {url[:80]}" for url in list(iocs['urls'])[:10]])
                story.append(Paragraph(url_list, styles['Normal']))
            
            story.append(Spacer(1, 0.3*inch))
            
            # Conclusions
            story.append(Paragraph("ANALYST CONCLUSION", heading_style))
            conclusion = self._generate_conclusion()
            story.append(Paragraph(conclusion, styles['Normal']))
            
            # Footer
            story.append(Spacer(1, 0.5*inch))
            footer_text = f"""
            <para align=center>
            ═══════════════════════════════════════════════════════════<br/>
            <b>END OF REPORT</b><br/>
            Generated by Network Packet Investigator v1.0.0<br/>
            {self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S')}
            </para>
            """
            story.append(Paragraph(footer_text, styles['Normal']))
            
            # Build PDF
            doc.build(story)
            
            self.logger.info(f"PDF report generated: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _generate_pdf_summary(self) -> str:
        """Generate executive summary for PDF."""
        proto_analysis = self.analysis_results.get('protocol_analysis', {})
        dns_analysis = self.analysis_results.get('dns_analysis', {})
        http_analysis = self.analysis_results.get('http_analysis', {})
        tcp_analysis = self.analysis_results.get('tcp_analysis', {})
        
        findings = self.detection_results.get('all_findings', [])
        high_severity = len([f for f in findings if f['severity'] == 'HIGH'])
        
        summary = f"""
        Analysis of network capture identified <b>{proto_analysis.get('total_packets', 0):,} packets</b> 
        across multiple protocols. The investigation revealed:<br/><br/>
        • <b>{dns_analysis.get('total_queries', 0):,}</b> DNS queries to <b>{dns_analysis.get('unique_domains', 0):,}</b> unique domains<br/>
        • <b>{http_analysis.get('total_requests', 0):,}</b> HTTP requests to <b>{http_analysis.get('unique_hosts', 0):,}</b> unique hosts<br/>
        • <b>{tcp_analysis.get('unique_connections', 0):,}</b> unique TCP connections<br/>
        • <b>{tcp_analysis.get('total_data_transferred', 0):,}</b> bytes transferred<br/><br/>
        <b>Threat Detection Results:</b><br/>
        • Total Findings: <b>{len(findings)}</b><br/>
        • <font color="red">High Severity: <b>{high_severity}</b></font><br/>
        • Medium Severity: <b>{len([f for f in findings if f['severity'] == 'MEDIUM'])}</b>
        """
        
        return summary
    
    def _create_protocol_chart(self):
        """Create protocol distribution chart for PDF."""
        try:
            proto_analysis = self.analysis_results.get('protocol_analysis', {})
            protocol_counts = proto_analysis.get('protocol_counts', {})
            
            if not protocol_counts:
                return None
            
            # Create pie chart
            fig, ax = plt.subplots(figsize=(6, 4))
            labels = list(protocol_counts.keys())
            sizes = list(protocol_counts.values())
            colors_list = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c']
            
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors_list)
            ax.set_title('Protocol Distribution', fontsize=14, fontweight='bold')
            
            # Save to BytesIO
            img_buffer = BytesIO()
            plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
            img_buffer.seek(0)
            plt.close()
            
            # Create ReportLab image
            img = RLImage(img_buffer, width=5*inch, height=3.3*inch)
            return img
            
        except Exception as e:
            self.logger.error(f"Error creating protocol chart: {str(e)}")
            return None
    
    def _extract_iocs_for_pdf(self) -> Dict[str, set]:
        """Extract IOCs for PDF report."""
        findings = self.detection_results.get('all_findings', [])
        
        iocs = {
            'domains': set(),
            'ips': set(),
            'urls': set()
        }
        
        for finding in findings:
            if 'domain' in finding:
                iocs['domains'].add(finding['domain'])
            if 'destination_ip' in finding:
                iocs['ips'].add(finding['destination_ip'])
            if 'url' in finding:
                iocs['urls'].add(finding['url'])
        
        return iocs
    
    def _generate_conclusion(self) -> str:
        """Generate analyst conclusion for PDF."""
        findings = self.detection_results.get('all_findings', [])
        high_severity = len([f for f in findings if f['severity'] == 'HIGH'])
        
        if high_severity > 0:
            conclusion = f"""
            Based on the forensic analysis of network traffic, this investigation identified 
            <b><font color="red">{high_severity} high-severity findings</font></b> indicating potential security incidents. 
            The evidence suggests possible security threats that require immediate attention.<br/><br/>
            <b>RECOMMENDATIONS:</b><br/>
            1. Isolate affected systems immediately<br/>
            2. Investigate identified indicators of compromise<br/>
            3. Review authentication logs for compromised credentials<br/>
            4. Conduct malware analysis on affected endpoints<br/>
            5. Implement network segmentation and monitoring<br/>
            6. Update security policies and user training
            """
        else:
            conclusion = f"""
            Based on the forensic analysis of network traffic, no high-severity threats were identified. 
            However, <b>{len(findings)} findings</b> require further investigation to ensure network security.<br/><br/>
            <b>RECOMMENDATIONS:</b><br/>
            1. Continue monitoring identified domains and IPs<br/>
            2. Review and update security policies as needed<br/>
            3. Maintain regular security audits<br/>
            4. Document baseline traffic patterns
            """
        
        return conclusion


if __name__ == "__main__":
    print("Forensic Reporter Module - Network Packet Investigator")
    print("=" * 60)
    print("This module is designed to be imported and used by the main application.")

