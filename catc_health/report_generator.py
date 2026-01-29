"""\nHealth Report Generator Module\n\nGenerates PDF health reports.\n"""\n\nimport os\nimport logging\nfrom typing import List, Dict, Optional, Any\nfrom datetime import datetime\n\nfrom reportlab.lib import colors\nfrom reportlab.lib.pagesizes import letter, A4\nfrom reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle\nfrom reportlab.lib.units import inch\nfrom reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak\nfrom reportlab.lib.enums import TA_CENTER, TA_LEFT\n\nfrom .utils import categorize_health\n\nclass HealthReportGenerator:
    """Generates health reports in PDF format"""

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the report generator

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir
        self.setup_output_directory()

    def setup_output_directory(self):
        """Create output directory if it doesn't exist"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logging.info(f"Created output directory: {self.output_dir}")

    def generate_device_health_pdf(self, devices: List[Dict[str, Any]],
                                  timestamp: Optional[str] = None) -> str:
        """
        Generate PDF report for device health data

        Args:
            devices: List of device health data
            timestamp: Timestamp for the report

        Returns:
            Path to the generated PDF file
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"device_health_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []

        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )

        # Add title
        title = Paragraph("Cisco Catalyst Center - Device Health Report", title_style)
        story.append(title)

        # Add timestamp
        timestamp_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        timestamp_para = Paragraph(timestamp_text, styles['Normal'])
        story.append(timestamp_para)
        story.append(Spacer(1, 20))

        # Add summary
        total_devices = len(devices)
        poor_devices = len([d for d in devices if d.get('overallHealth', 0) <= 3])
        fair_devices = len([d for d in devices if 3 < d.get('overallHealth', 0) <= 7])
        good_devices = len([d for d in devices if d.get('overallHealth', 0) > 7])

        summary_data = [
            ['Summary', 'Count'],
            ['Total Devices', str(total_devices)],
            ['Poor Health (≤3)', str(poor_devices)],
            ['Fair Health (4-7)', str(fair_devices)],
            ['Good Health (>7)', str(good_devices)]
        ]

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        if devices:
            # Create table data
            table_data = [
                ['Device Name', 'IP Address', 'Type', 'Health Score', 'Status', 'Location']
            ]

            for device in devices:
                health_score = device.get('overallHealth', 'N/A')
                health_str = str(health_score) if health_score != 'N/A' else 'N/A'

                # Determine health status
                if isinstance(health_score, (int, float)):
                    if health_score <= 3:
                        status = 'POOR'
                    elif health_score <= 7:
                        status = 'FAIR'
                    else:
                        status = 'GOOD'
                else:
                    status = 'UNKNOWN'

                row = [
                    device.get('name', 'N/A'),              # Fixed field name
                    device.get('ipAddress', 'N/A'),         # Fixed field name
                    device.get('deviceType', 'N/A'),        # Fixed field name
                    health_str,
                    status,
                    device.get('location', 'N/A')           # More useful than lastUpdated
                ]
                table_data.append(row)

            # Create table
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(Paragraph("Device Health Details", styles['Heading2']))
            story.append(Spacer(1, 12))
            story.append(table)
        else:
            story.append(Paragraph("No device health data available.", styles['Normal']))

        # Build PDF
        doc.build(story)

        logging.info(f"Device health PDF report generated: {filepath}")
        return filepath

    def generate_issues_pdf(self, issues: List[Dict[str, Any]],
                           timestamp: Optional[str] = None) -> str:
        """
        Generate PDF report for assurance issues

        Args:
            issues: List of assurance issues
            timestamp: Timestamp for the report

        Returns:
            Path to the generated PDF file
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"all_issues_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []

        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )

        # Add title
        title = Paragraph("Cisco Catalyst Center - All Issues Report", title_style)
        story.append(title)

        # Add subtitle
        subtitle = Paragraph("(Assurance Issues + Critical/High Priority Intent Issues)", styles['Normal'])
        story.append(subtitle)

        # Add timestamp
        timestamp_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        timestamp_para = Paragraph(timestamp_text, styles['Normal'])
        story.append(timestamp_para)
        story.append(Spacer(1, 20))

        # Add summary
        total_issues = len(issues)
        p1_issues = len([i for i in issues if i.get('priority') == 'P1'])
        p2_issues = len([i for i in issues if i.get('priority') == 'P2'])
        p3_issues = len([i for i in issues if i.get('priority') == 'P3'])
        p4_issues = len([i for i in issues if i.get('priority') == 'P4'])

        summary_data = [
            ['Issue Priority', 'Count'],
            ['Total Issues', str(total_issues)],
            ['P1 (Critical)', str(p1_issues)],
            ['P2 (High)', str(p2_issues)],
            ['P3 (Medium)', str(p3_issues)],
            ['P4 (Low)', str(p4_issues)]
        ]

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        if issues:
            # Create table data
            table_data = [
                ['Issue ID', 'Name', 'Priority', 'Status', 'Category', 'Source', 'Device Count']
            ]

            for issue in issues:
                # Determine source of issue based on available fields
                # Intent issues typically have different field structure than assurance issues
                if 'issueId' in issue and 'deviceCount' in issue:
                    source = 'Assurance'
                else:
                    source = 'Intent'

                row = [
                    issue.get('issueId', issue.get('id', 'N/A')),
                    issue.get('name', issue.get('title', 'N/A'))[:45] + ('...' if len(issue.get('name', issue.get('title', ''))) > 45 else ''),
                    issue.get('priority', 'N/A'),
                    issue.get('status', issue.get('issueStatus', 'N/A')),
                    issue.get('category', issue.get('issueCategory', 'N/A')),
                    source,
                    str(issue.get('deviceCount', issue.get('affectedDevices', 'N/A')))
                ]
                table_data.append(row)

            # Create table
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(Paragraph("Issues Details", styles['Heading2']))
            story.append(Spacer(1, 12))
            story.append(table)
        else:
            story.append(Paragraph("No assurance issues found.", styles['Normal']))

        # Build PDF
        doc.build(story)

        logging.info(f"Assurance issues PDF report generated: {filepath}")
        return filepath

    def generate_fabric_health_pdf(self, fabric_sites: List[Dict[str, Any]],
                                  fabric_health: List[Dict[str, Any]],
                                  timestamp: Optional[str] = None) -> str:
        """
        Generate PDF report for SDA fabric health

        Args:
            fabric_sites: List of fabric sites data
            fabric_health: List of fabric site health data
            timestamp: Timestamp for the report

        Returns:
            Path to the generated PDF file
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"sda_fabric_health_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []

        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )

        # Add title
        title = Paragraph("Cisco Catalyst Center - SDA Fabric Health Report", title_style)
        story.append(title)

        # Add timestamp
        timestamp_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        timestamp_para = Paragraph(timestamp_text, styles['Normal'])
        story.append(timestamp_para)
        story.append(Spacer(1, 20))

        # Combine fabric sites with health data
        combined_data = []
        for health in fabric_health:
            site_info = next((site for site in fabric_sites if site.get('id') == health.get('id')), {})
            combined_data.append({**site_info, **health})

        # Add summary
        total_sites = len(combined_data)
        healthy_sites = len([s for s in combined_data if s.get('goodHealthPercentage', 0) >= 80])
        warning_sites = len([s for s in combined_data if 50 <= s.get('goodHealthPercentage', 0) < 80])
        critical_sites = len([s for s in combined_data if s.get('goodHealthPercentage', 0) < 50])

        summary_data = [
            ['Fabric Health Summary', 'Count'],
            ['Total Fabric Sites', str(total_sites)],
            ['Healthy Sites (≥80%)', str(healthy_sites)],
            ['Warning Sites (50-79%)', str(warning_sites)],
            ['Critical Sites (<50%)', str(critical_sites)]
        ]

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        if combined_data:
            # Create table data
            table_data = [
                ['Site Name', 'Site Hierarchy', 'Health %', 'Status', 'Control Plane', 'Data Plane', 'Border Devices']
            ]

            for site in combined_data:
                health_percentage = site.get('goodHealthPercentage', 0)

                # Determine health status
                if health_percentage >= 80:
                    status = 'HEALTHY'
                elif health_percentage >= 50:
                    status = 'WARNING'
                else:
                    status = 'CRITICAL'

                # Extract health metrics
                control_plane_health = site.get('controlPlaneGoodHealthPercentage', 'N/A')
                data_plane_health = site.get('dataPlaneGoodHealthPercentage', 'N/A')
                border_device_count = site.get('borderDeviceCount', 'N/A')

                row = [
                    site.get('siteName', site.get('siteNameHierarchy', 'N/A'))[:25] + ('...' if len(site.get('siteName', site.get('siteNameHierarchy', ''))) > 25 else ''),
                    site.get('siteHierarchy', site.get('siteNameHierarchy', 'N/A'))[:30] + ('...' if len(site.get('siteHierarchy', site.get('siteNameHierarchy', ''))) > 30 else ''),
                    f"{health_percentage:.1f}%" if isinstance(health_percentage, (int, float)) else str(health_percentage),
                    status,
                    f"{control_plane_health:.1f}%" if isinstance(control_plane_health, (int, float)) else str(control_plane_health),
                    f"{data_plane_health:.1f}%" if isinstance(data_plane_health, (int, float)) else str(data_plane_health),
                    str(border_device_count)
                ]
                table_data.append(row)

            # Create table
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(Paragraph("Fabric Site Health Details", styles['Heading2']))
            story.append(Spacer(1, 12))
            story.append(table)
        else:
            story.append(Paragraph("No fabric sites or health data available.", styles['Normal']))

        # Build PDF
        doc.build(story)

        logging.info(f"SDA fabric health PDF report generated: {filepath}")
        return filepath

    def generate_application_health_pdf(self, applications: List[Dict[str, Any]],
                                       timestamp: Optional[str] = None) -> str:
        """
        Generate PDF report for application health

        Args:
            applications: List of application health data
            timestamp: Timestamp for the report

        Returns:
            Path to the generated PDF file
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"application_health_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []

        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )

        # Add title
        title = Paragraph("Cisco Catalyst Center - Application Health Report", title_style)
        story.append(title)

        # Add timestamp
        timestamp_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        timestamp_para = Paragraph(timestamp_text, styles['Normal'])
        story.append(timestamp_para)
        story.append(Spacer(1, 20))

        # Add summary
        total_applications = len(applications)
        poor_applications = len([a for a in applications if self._categorize_app_health(a.get('healthScore', 0)) == 'POOR'])
        fair_applications = len([a for a in applications if self._categorize_app_health(a.get('healthScore', 0)) == 'FAIR'])
        good_applications = len([a for a in applications if self._categorize_app_health(a.get('healthScore', 0)) == 'GOOD'])

        summary_data = [
            ['Application Health Summary', 'Count'],
            ['Total Applications', str(total_applications)],
            ['Poor Health', str(poor_applications)],
            ['Fair Health', str(fair_applications)],
            ['Good Health', str(good_applications)]
        ]

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        if applications:
            # Create table data
            table_data = [
                ['Application Name', 'Health Score', 'Status', 'Usage', 'Throughput', 'Packet Loss %', 'Network Latency']
            ]

            for app in applications:
                health_score = app.get('healthScore', 0)
                health_status = self._categorize_app_health(health_score)

                # Format metrics
                usage = app.get('usage', 'N/A')
                if isinstance(usage, (int, float)):
                    usage = f"{usage:.2f}"

                throughput = app.get('throughput', 'N/A')
                if isinstance(throughput, (int, float)):
                    throughput = f"{throughput:.2f} Mbps"

                packet_loss = app.get('packetLossPercent', 'N/A')
                if isinstance(packet_loss, (int, float)):
                    packet_loss = f"{packet_loss:.2f}%"

                network_latency = app.get('networkLatency', 'N/A')
                if isinstance(network_latency, (int, float)):
                    network_latency = f"{network_latency:.2f} ms"

                row = [
                    app.get('applicationName', 'N/A')[:25] + ('...' if len(app.get('applicationName', '')) > 25 else ''),
                    f"{health_score:.1f}" if isinstance(health_score, (int, float)) else str(health_score),
                    health_status,
                    str(usage),
                    str(throughput),
                    str(packet_loss),
                    str(network_latency)
                ]
                table_data.append(row)

            # Create table
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(Paragraph("Application Health Details", styles['Heading2']))
            story.append(Spacer(1, 12))
            story.append(table)
        else:
            story.append(Paragraph("No application health data available.", styles['Normal']))

        # Build PDF
        doc.build(story)

        logging.info(f"Application health PDF report generated: {filepath}")
        return filepath

    def _categorize_app_health(self, health_score: Any) -> str:
        """
        Categorize application health based on health score

        Args:
            health_score: Health score value

        Returns:
            Health category (POOR, FAIR, GOOD)
        """
        if not isinstance(health_score, (int, float)):
            return 'UNKNOWN'

        if health_score < 4:
            return 'POOR'
        elif health_score < 7:
            return 'FAIR'
        else:
            return 'GOOD'

    def generate_client_health_pdf(self, clients: List[Dict[str, Any]],
                                  timestamp: Optional[str] = None) -> str:
        """
        Generate PDF report for client health

        Args:
            clients: List of client health data
            timestamp: Timestamp for the report

        Returns:
            Path to the generated PDF file
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"client_health_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []

        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )

        # Add title
        title = Paragraph("Cisco Catalyst Center - Client Health Report", title_style)
        story.append(title)

        # Add timestamp
        timestamp_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        timestamp_para = Paragraph(timestamp_text, styles['Normal'])
        story.append(timestamp_para)
        story.append(Spacer(1, 20))

        # Add summary by connection type
        total_clients = len(clients)
        wired_clients = [c for c in clients if c.get('type', '').lower() == 'wired']
        wireless_clients = [c for c in clients if c.get('type', '').lower() == 'wireless']

        # Health categorization for all clients
        poor_clients = len([c for c in clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'POOR'])
        fair_clients = len([c for c in clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'FAIR'])
        good_clients = len([c for c in clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'GOOD'])

        # Health categorization for wired clients
        wired_poor = len([c for c in wired_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'POOR'])
        wired_fair = len([c for c in wired_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'FAIR'])
        wired_good = len([c for c in wired_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'GOOD'])

        # Health categorization for wireless clients
        wireless_poor = len([c for c in wireless_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'POOR'])
        wireless_fair = len([c for c in wireless_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'FAIR'])
        wireless_good = len([c for c in wireless_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'GOOD'])

        summary_data = [
            ['Client Summary', 'Total', 'Poor', 'Fair', 'Good'],
            ['All Clients', str(total_clients), str(poor_clients), str(fair_clients), str(good_clients)],
            ['Wired Clients', str(len(wired_clients)), str(wired_poor), str(wired_fair), str(wired_good)],
            ['Wireless Clients', str(len(wireless_clients)), str(wireless_poor), str(wireless_fair), str(wireless_good)]
        ]

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        if clients:
            # Create table data for detailed client information
            table_data = [
                ['MAC Address', 'IP Address', 'Connection Type', 'Health Score', 'Status', 'SSID', 'Location']
            ]

            for client in clients:
                # Get health score from nested health object
                health_info = client.get('health', {})
                health_score = health_info.get('overallScore', 0)
                health_status = self._categorize_client_health(health_score)

                # Format MAC address for better readability
                mac_address = client.get('macAddress', 'N/A')
                if len(mac_address) > 12:
                    mac_address = mac_address[:12] + '...'

                # Format location for better readability
                location = client.get('siteHierarchy', 'N/A')
                if len(location) > 25:
                    location = location[:22] + '...'

                # Get connection info
                connection_type = client.get('type', 'N/A').title()
                connection_info = client.get('connection', {})
                ssid = connection_info.get('ssid', 'N/A') if connection_type.lower() == 'wireless' else 'N/A'

                row = [
                    mac_address,
                    client.get('ipv4Address', 'N/A'),
                    connection_type,
                    f"{health_score:.1f}" if isinstance(health_score, (int, float)) else str(health_score),
                    health_status,
                    ssid,
                    location
                ]
                table_data.append(row)

            # Create table
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(Paragraph("Client Health Details", styles['Heading2']))
            story.append(Spacer(1, 12))
            story.append(table)
        else:
            story.append(Paragraph("No client health data available.", styles['Normal']))

        # Build PDF
        doc.build(story)

        logging.info(f"Client health PDF report generated: {filepath}")
        return filepath

    def _categorize_client_health(self, health_score: Any) -> str:
        """
        Categorize client health based on health score

        Args:
            health_score: Health score value

        Returns:
            Health category (POOR, FAIR, GOOD)
        """
        if not isinstance(health_score, (int, float)):
            return 'UNKNOWN'

        if health_score < 4:
            return 'POOR'
        elif health_score < 7:
            return 'FAIR'
        else:
            return 'GOOD'

    def generate_system_health_pdf(self, ise_health: List[Dict[str, Any]],
                                  maglev_services: List[Dict[str, Any]],
                                  system_backup: List[Dict[str, Any]],
                                  backup_history: List[Dict[str, Any]],
                                  system_updates: Dict[str, Any],
                                  timestamp: Optional[str] = None) -> str:
        """
        Generate PDF report for system health (ISE, Maglev, Backups, Updates)

        Args:
            ise_health: List of ISE health data
            maglev_services: List of Maglev services data
            system_backup: List of system backup data
            backup_history: List of backup history data
            system_updates: System update information
            timestamp: Timestamp for the report

        Returns:
            Path to the generated PDF file
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"system_health_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []

        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )

        # Add title
        title = Paragraph("Cisco Catalyst Center - System Health Report", title_style)
        story.append(title)

        # Add timestamp
        timestamp_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        timestamp_para = Paragraph(timestamp_text, styles['Normal'])
        story.append(timestamp_para)
        story.append(Spacer(1, 20))

        # ISE Health Section
        story.append(Paragraph("Cisco ISE Health Status", styles['Heading2']))
        story.append(Spacer(1, 12))

        if ise_health:
            # ISE Summary
            total_ise_nodes = len(ise_health)
            available_nodes = len([n for n in ise_health if n.get('status') == 'AVAILABLE'])
            unavailable_nodes = total_ise_nodes - available_nodes

            ise_summary_data = [
                ['ISE Health Summary', 'Count'],
                ['Total ISE Nodes', str(total_ise_nodes)],
                ['Available Nodes', str(available_nodes)],
                ['Unavailable Nodes', str(unavailable_nodes)]
            ]

            ise_summary_table = Table(ise_summary_data)
            ise_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(ise_summary_table)
            story.append(Spacer(1, 20))

            # ISE Details Table
            ise_table_data = [
                ['FQDN', 'IP Address', 'Role', 'Status', 'Last Update']
            ]

            for node in ise_health:
                last_update = node.get('lastStatusUpdateTime', 0)
                if isinstance(last_update, (int, float)) and last_update > 0:
                    last_update_str = datetime.fromtimestamp(last_update / 1000).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    last_update_str = 'N/A'

                row = [
                    node.get('fqdn', 'N/A')[:30] + ('...' if len(node.get('fqdn', '')) > 30 else ''),
                    node.get('ip', 'N/A'),
                    node.get('role', 'N/A'),
                    node.get('status', 'N/A'),
                    last_update_str
                ]
                ise_table_data.append(row)

            ise_table = Table(ise_table_data)
            ise_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(ise_table)
        else:
            story.append(Paragraph("No ISE health data available.", styles['Normal']))

        story.append(PageBreak())

        # Maglev Services Section
        story.append(Paragraph("Maglev Services Status", styles['Heading2']))
        story.append(Spacer(1, 12))

        if maglev_services:
            # Maglev Summary
            total_services = len(maglev_services)
            running_services = 0
            ready_services = 0

            for service in maglev_services:
                instances = service.get('instances', [])
                for instance in instances:
                    status = instance.get('status', {})
                    if status.get('state') == 'Running':
                        running_services += 1
                    if status.get('ready'):
                        ready_services += 1

            maglev_summary_data = [
                ['Maglev Services Summary', 'Count'],
                ['Total Services', str(total_services)],
                ['Running Instances', str(running_services)],
                ['Ready Instances', str(ready_services)]
            ]

            maglev_summary_table = Table(maglev_summary_data)
            maglev_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(maglev_summary_table)
            story.append(Spacer(1, 20))

            # Note about detailed services
            note_text = f"Note: Showing summary for {total_services} Maglev services. Full service details available in system logs."
            story.append(Paragraph(note_text, styles['Normal']))
        else:
            story.append(Paragraph("No Maglev services data available.", styles['Normal']))

        story.append(PageBreak())

        # System Backup Section
        story.append(Paragraph("System Backup Information", styles['Heading2']))
        story.append(Spacer(1, 12))

        if system_backup:
            # Backup Summary
            total_backups = len(system_backup)
            successful_backups = len([b for b in system_backup if b.get('status') == 'SUCCESS'])
            failed_backups = total_backups - successful_backups

            backup_summary_data = [
                ['Backup Summary', 'Count'],
                ['Total Backups', str(total_backups)],
                ['Successful Backups', str(successful_backups)],
                ['Failed Backups', str(failed_backups)]
            ]

            backup_summary_table = Table(backup_summary_data)
            backup_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(backup_summary_table)
            story.append(Spacer(1, 20))

            # Backup Details Table
            backup_table_data = [
                ['Backup ID', 'Description', 'Status', 'Start Time', 'Size', 'Compatible']
            ]

            for backup in system_backup:
                start_time = backup.get('start_timestamp', 0)
                if isinstance(start_time, (int, float)) and start_time > 0:
                    start_time_str = datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M')
                else:
                    start_time_str = 'N/A'

                backup_size = backup.get('backup_size', 'N/A')
                if isinstance(backup_size, (int, float)):
                    backup_size_str = f"{backup_size / (1024**3):.1f} GB"
                else:
                    backup_size_str = str(backup_size)

                row = [
                    backup.get('backup_id', 'N/A')[:20] + ('...' if len(backup.get('backup_id', '')) > 20 else ''),
                    backup.get('description', 'N/A')[:15] + ('...' if len(backup.get('description', '')) > 15 else ''),
                    backup.get('status', 'N/A'),
                    start_time_str,
                    backup_size_str,
                    str(backup.get('compatible', 'N/A'))
                ]
                backup_table_data.append(row)

            backup_table = Table(backup_table_data)
            backup_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(backup_table)
        else:
            story.append(Paragraph("No system backup data available.", styles['Normal']))

        story.append(PageBreak())

        # System Updates Section
        story.append(Paragraph("System Update Information", styles['Heading2']))
        story.append(Spacer(1, 12))

        if system_updates:
            update_table_data = [
                ['Update Information', 'Value'],
                ['Latest Available Version', str(system_updates.get('latestAvailableVersion', 'N/A'))],
                ['Update Package Status', str(system_updates.get('latestUpdatePackageStatus', 'N/A'))],
                ['Status Message', str(system_updates.get('latestUpdatePackageStatusMessage', 'N/A'))]
            ]

            update_table = Table(update_table_data)
            update_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(update_table)
        else:
            story.append(Paragraph("No system update information available.", styles['Normal']))

        # Build PDF
        doc.build(story)

        logging.info(f"System health PDF report generated: {filepath}")
        return filepath

    def generate_combined_pdf(self, devices: List[Dict[str, Any]],
                             all_devices: List[Dict[str, Any]],
                             issues: List[Dict[str, Any]],
                             fabric_sites: Optional[List[Dict[str, Any]]] = None,
                             fabric_health: Optional[List[Dict[str, Any]]] = None,
                             all_sites: Optional[List[Dict[str, Any]]] = None,
                             applications: Optional[List[Dict[str, Any]]] = None,
                             clients: Optional[List[Dict[str, Any]]] = None,
                             ise_health: Optional[List[Dict[str, Any]]] = None,
                             maglev_services: Optional[List[Dict[str, Any]]] = None,
                             system_backup: Optional[List[Dict[str, Any]]] = None,
                             backup_history: Optional[List[Dict[str, Any]]] = None,
                             system_updates: Optional[Dict[str, Any]] = None,
                             eox_status: Optional[List[Dict[str, Any]]] = None,
                             non_compliant_devices: Optional[List[Dict[str, Any]]] = None,
                             families_without_golden: Optional[List[str]] = None,
                             timestamp: Optional[str] = None) -> str:
        """
        Generate comprehensive PDF report with all health data

        Args:
            devices: List of device health data (filtered for poor/fair)
            all_devices: List of all device health data (for executive summary calculations)
            issues: List of assurance and intent issues (P1/P2)
            fabric_sites: List of fabric sites data
            fabric_health: List of fabric site health data
            all_sites: List of all sites data for site name mapping
            applications: List of application health data
            clients: List of client health data
            ise_health: List of ISE health data
            maglev_services: List of Maglev services data
            system_backup: List of system backup data
            backup_history: List of backup history data
            system_updates: System update information
            eox_status: List of devices with EoX status
            non_compliant_devices: List of non-compliant devices
            families_without_golden: List of device families without golden images
            timestamp: Timestamp for the report

        Returns:
            Path to the generated PDF file
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"catalyst_comprehensive_health_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []

        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=TA_CENTER
        )

        # Add main title
        title = Paragraph("Cisco Catalyst Center - Comprehensive Health Report", title_style)
        story.append(title)

        # Add timestamp
        timestamp_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        timestamp_para = Paragraph(timestamp_text, styles['Normal'])
        story.append(timestamp_para)
        story.append(Spacer(1, 30))

        # Calculate summary statistics for executive summary
        # Device health summary - use all devices for proper counts
        total_devices = len(all_devices)
        poor_devices = len([d for d in all_devices if d.get('overallHealth', 0) <= 3])
        fair_devices = len([d for d in all_devices if 3 < d.get('overallHealth', 0) <= 7])
        good_devices = len([d for d in all_devices if d.get('overallHealth', 0) > 7])

        # Issues summary
        total_issues = len(issues)
        critical_issues = len([i for i in issues if i.get('priority') == 'P1'])
        high_issues = len([i for i in issues if i.get('priority') == 'P2'])

        # Separate assurance and intent issues for reporting
        assurance_issues_count = len([i for i in issues if 'issueId' in i and 'deviceCount' in i])
        intent_issues_count = total_issues - assurance_issues_count

        # Fabric health summary
        fabric_health = fabric_health or []
        all_sites = all_sites or []
        total_fabric_sites = len(fabric_health)
        healthy_fabric_sites = len([s for s in fabric_health if s.get('goodHealthPercentage', 0) >= 80])

        # Application health summary
        applications = applications or []
        total_applications = len(applications)
        poor_applications = len([a for a in applications if self._categorize_app_health(a.get('healthScore', 0)) == 'POOR'])
        fair_applications = len([a for a in applications if self._categorize_app_health(a.get('healthScore', 0)) == 'FAIR'])

        # Client health summary (fix field names for Data API)
        clients = clients or []
        total_clients = len(clients)
        wired_clients = [c for c in clients if c.get('type', '').lower() == 'wired']
        wireless_clients = [c for c in clients if c.get('type', '').lower() == 'wireless']
        poor_clients = len([c for c in clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'POOR'])
        fair_clients = len([c for c in clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'FAIR'])

        # Wired client health
        wired_poor = len([c for c in wired_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'POOR'])
        wired_fair = len([c for c in wired_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'FAIR'])

        # Wireless client health
        wireless_poor = len([c for c in wireless_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'POOR'])
        wireless_fair = len([c for c in wireless_clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'FAIR'])

        # System health summary
        ise_health = ise_health or []
        maglev_services = maglev_services or []
        system_backup = system_backup or []
        system_updates = system_updates or {}

        total_ise_nodes = len(ise_health)
        available_ise_nodes = len([n for n in ise_health if n.get('status') == 'AVAILABLE'])
        total_maglev_services = len(maglev_services)
        total_backups = len(system_backup)
        successful_backups = len([b for b in system_backup if b.get('status') == 'SUCCESS'])
        update_status = system_updates.get('latestUpdatePackageStatus', 'UNKNOWN')

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        story.append(Spacer(1, 12))

        # Create a more readable executive summary with tables instead of bullet points

        # Device Health Breakdown
        device_health_data = [
            ['Health Category', 'Count', 'Percentage'],
            ['Poor Health (≤3)', str(poor_devices), f"{(poor_devices/max(total_devices,1)*100):.1f}%"],
            ['Fair Health (4-7)', str(fair_devices), f"{(fair_devices/max(total_devices,1)*100):.1f}%"],
            ['Good Health (>7)', str(good_devices), f"{(good_devices/max(total_devices,1)*100):.1f}%"]
        ]

        device_health_table = Table(device_health_data, colWidths=[2.5*inch, 1*inch, 1.5*inch])
        device_health_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.green),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))

        story.append(Paragraph("Device Health Breakdown", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(device_health_table)
        story.append(Spacer(1, 20))

        # Issues Summary
        if total_issues > 0:
            issues_data = [
                ['Issue Type', 'Count'],
                ['Critical Issues (P1)', str(critical_issues)],
                ['High Priority Issues (P2)', str(high_issues)]
            ]

            issues_table = Table(issues_data, colWidths=[3*inch, 1.5*inch])
            issues_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.mistyrose),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
            ]))

            story.append(Paragraph("Critical & High Priority Issues", styles['Heading3']))
            story.append(Spacer(1, 6))
            story.append(issues_table)
            story.append(Spacer(1, 20))
        else:
            story.append(Paragraph("✅ No Critical or High Priority Issues Found", styles['Heading3']))
            story.append(Spacer(1, 20))

        # 4. Client Health Summary (if clients exist)
        if total_clients > 0:
            client_health_data = [
                ['Connection Type', 'Total', 'Poor Health', 'Fair Health', 'Good Health'],
                ['Wired Clients', str(len(wired_clients)), str(wired_poor), str(wired_fair), str(len(wired_clients) - wired_poor - wired_fair)],
                ['Wireless Clients', str(len(wireless_clients)), str(wireless_poor), str(wireless_fair), str(len(wireless_clients) - wireless_poor - wireless_fair)],
                ['All Clients', str(total_clients), str(poor_clients), str(fair_clients), str(total_clients - poor_clients - fair_clients)]
            ]

            client_health_table = Table(client_health_data, colWidths=[1.5*inch, 0.8*inch, 1*inch, 1*inch, 1*inch])
            client_health_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
            ]))

            story.append(Paragraph("Client Health Summary", styles['Heading3']))
            story.append(Spacer(1, 6))
            story.append(client_health_table)
            story.append(Spacer(1, 20))

        # System Health Summary
        system_health_data = [
            ['System Component', 'Status'],
            ['ISE Integration', f"{available_ise_nodes}/{total_ise_nodes} Available" if total_ise_nodes > 0 else "Not Available"],
            ['System Services', f"{len([s for s in maglev_services if s.get('status') == 'running'])}/{total_maglev_services} Running" if total_maglev_services > 0 else "Unknown"],
            ['System Backups', f"{successful_backups}/{total_backups} Successful" if total_backups > 0 else "No Data"],
            ['Software Updates', update_status]
        ]

        system_health_table = Table(system_health_data, colWidths=[3*inch, 2*inch])
        system_health_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.purple),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lavender),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))

        story.append(Paragraph("System Health Summary", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(system_health_table)
        story.append(PageBreak())

        # Device Health Section
        story.append(Paragraph("Device Health Report", styles['Heading2']))
        story.append(Spacer(1, 12))

        if devices:
            # Device health table
            device_table_data = [
                ['Device Name', 'IP Address', 'Type', 'Health Score', 'Status', 'Location']
            ]

            for device in devices:
                health_score = device.get('overallHealth', 'N/A')
                health_str = str(health_score) if health_score != 'N/A' else 'N/A'

                # Determine health status
                if isinstance(health_score, (int, float)):
                    if health_score <= 3:
                        status = 'POOR'
                    elif health_score <= 7:
                        status = 'FAIR'
                    else:
                        status = 'GOOD'
                else:
                    status = 'UNKNOWN'

                # Get device location and truncate if too long
                location = device.get('location', 'N/A')
                if location != 'N/A' and len(location) > 40:
                    location = location[:37] + '...'

                row = [
                    device.get('name', 'N/A'),                    # Correct field name
                    device.get('ipAddress', 'N/A'),              # Correct field name
                    device.get('deviceType', 'N/A'),             # Correct field name
                    health_str,
                    status,
                    location
                ]
                device_table_data.append(row)

            device_table = Table(device_table_data)
            device_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(device_table)
        else:
            story.append(Paragraph("No device health data available.", styles['Normal']))

        story.append(PageBreak())

        # Issues Section
        story.append(Paragraph("Critical & High Priority Issues (P1/P2)", styles['Heading2']))
        story.append(Spacer(1, 12))

        if issues:
            # Issues table
            issues_table_data = [
                ['Name', 'Priority', 'Status', 'Category', 'Device Count']
            ]

            for issue in issues:
                # Determine device count based on available fields
                device_count = issue.get('deviceCount', issue.get('affectedDevices', 'N/A'))

                row = [
                    issue.get('name', issue.get('title', 'N/A'))[:50] + ('...' if len(issue.get('name', issue.get('title', ''))) > 50 else ''),
                    issue.get('priority', 'N/A'),
                    issue.get('status', issue.get('issueStatus', 'N/A')),
                    issue.get('category', issue.get('issueCategory', 'N/A')),
                    str(device_count)
                ]
                issues_table_data.append(row)

            issues_table = Table(issues_table_data)
            issues_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(issues_table)
        else:
            story.append(Paragraph("No critical or high priority issues found.", styles['Normal']))

        # SDA Fabric Health Section
        if fabric_health:
            story.append(PageBreak())
            story.append(Paragraph("SDA Fabric Health Report", styles['Heading2']))
            story.append(Spacer(1, 12))

            # Process fabric health data - the API already includes site names!
            processed_fabric_data = []
            for health in fabric_health:
                # The fabric health API already includes the site name in the 'name' field
                site_name = health.get('name', 'Unknown Site')

                # Extract just the site name from hierarchy if it's a full path
                if '/' in site_name:
                    display_name = site_name.split('/')[-1].strip()
                else:
                    display_name = site_name

                # Get site ID for reference
                fabric_site_id = health.get('id', '')

                # Combine health data with resolved names
                combined_data = {**health}
                combined_data['resolved_site_name'] = display_name
                combined_data['resolved_site_hierarchy'] = site_name  # Full hierarchy
                combined_data['fabric_site_id'] = fabric_site_id
                processed_fabric_data.append(combined_data)

            # Fabric Health table
            fabric_table_data = [
                ['Site Name', 'Site Hierarchy', 'Health %', 'Status']
            ]

            for site in processed_fabric_data:
                health_percentage = site.get('goodHealthPercentage', 0)

                # Determine health status
                if health_percentage >= 80:
                    status = 'HEALTHY'
                elif health_percentage >= 50:
                    status = 'WARNING'
                else:
                    status = 'CRITICAL'

                site_name = site.get('resolved_site_name', 'N/A')
                site_hierarchy = site.get('resolved_site_hierarchy', 'N/A')

                row = [
                    site_name[:35] + ('...' if len(site_name) > 35 else ''),
                    site_hierarchy[:40] + ('...' if len(site_hierarchy) > 40 else '') if site_hierarchy != 'N/A' else 'N/A',
                    f"{health_percentage:.1f}%" if isinstance(health_percentage, (int, float)) else str(health_percentage),
                    status
                ]
                fabric_table_data.append(row)

            fabric_table = Table(fabric_table_data)
            fabric_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(fabric_table)

        # Application Health Section
        if applications:
            story.append(PageBreak())
            story.append(Paragraph("Application Health Report", styles['Heading2']))
            story.append(Spacer(1, 12))

            # Application Health table
            app_table_data = [
                ['Application Name', 'Health Score', 'Status', 'Usage', 'Throughput', 'Packet Loss %']
            ]

            for app in applications:
                health_score = app.get('healthScore', 0)
                health_status = self._categorize_app_health(health_score)

                # Format metrics
                usage = app.get('usage', 'N/A')
                if isinstance(usage, (int, float)):
                    usage = f"{usage:.2f}"

                throughput = app.get('throughput', 'N/A')
                if isinstance(throughput, (int, float)):
                    throughput = f"{throughput:.2f} Mbps"

                packet_loss = app.get('packetLossPercent', 'N/A')
                if isinstance(packet_loss, (int, float)):
                    packet_loss = f"{packet_loss:.2f}%"

                row = [
                    app.get('applicationName', 'N/A')[:30] + ('...' if len(app.get('applicationName', '')) > 30 else ''),
                    f"{health_score:.1f}" if isinstance(health_score, (int, float)) else str(health_score),
                    health_status,
                    str(usage),
                    str(throughput),
                    str(packet_loss)
                ]
                app_table_data.append(row)

            app_table = Table(app_table_data)
            app_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(app_table)

        # Client Health Section
        if clients:
            story.append(PageBreak())
            story.append(Paragraph("Client Health Report", styles['Heading2']))
            story.append(Spacer(1, 12))

            # Client summary by connection type
            total_clients = len(clients)
            wired_clients = [c for c in clients if c.get('connectionType', '').lower() == 'wired']
            wireless_clients = [c for c in clients if c.get('connectionType', '').lower() == 'wireless']

            # Health categorization for all clients
            poor_clients = len([c for c in clients if self._categorize_client_health(c.get('healthScore', 0)) == 'POOR'])
            fair_clients = len([c for c in clients if self._categorize_client_health(c.get('healthScore', 0)) == 'FAIR'])
            good_clients = len([c for c in clients if self._categorize_client_health(c.get('healthScore', 0)) == 'GOOD'])

            # Health categorization for wired clients
            wired_poor = len([c for c in wired_clients if self._categorize_client_health(c.get('healthScore', 0)) == 'POOR'])
            wired_fair = len([c for c in wired_clients if self._categorize_client_health(c.get('healthScore', 0)) == 'FAIR'])
            wired_good = len([c for c in wired_clients if self._categorize_client_health(c.get('healthScore', 0)) == 'GOOD'])

            # Health categorization for wireless clients
            wireless_poor = len([c for c in wireless_clients if self._categorize_client_health(c.get('healthScore', 0)) == 'POOR'])
            wireless_fair = len([c for c in wireless_clients if self._categorize_client_health(c.get('healthScore', 0)) == 'FAIR'])
            wireless_good = len([c for c in wireless_clients if self._categorize_client_health(c.get('healthScore', 0)) == 'GOOD'])

            client_summary_data = [
                ['Client Summary', 'Total', 'Poor', 'Fair', 'Good'],
                ['All Clients', str(total_clients), str(poor_clients), str(fair_clients), str(good_clients)],
                ['Wired Clients', str(len(wired_clients)), str(wired_poor), str(wired_fair), str(wired_good)],
                ['Wireless Clients', str(len(wireless_clients)), str(wireless_poor), str(wireless_fair), str(wireless_good)]
            ]

            client_summary_table = Table(client_summary_data)
            client_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(client_summary_table)
            story.append(Spacer(1, 20))

            # Client Details Table
            client_table_data = [
                ['Client ID', 'MAC Address', 'Connection Type', 'Health Score', 'Status', 'Connected Device']
            ]

            for client in clients:
                health_score = client.get('healthScore', 0)
                health_status = self._categorize_client_health(health_score)

                row = [
                    client.get('id', client.get('clientId', 'N/A'))[:15] + ('...' if len(client.get('id', client.get('clientId', ''))) > 15 else ''),
                    client.get('macAddress', 'N/A'),
                    client.get('connectionType', 'N/A'),
                    f"{health_score:.1f}" if isinstance(health_score, (int, float)) else str(health_score),
                    health_status,
                    client.get('connectedDevice', {}).get('name', client.get('deviceName', 'N/A'))[:20] + ('...' if len(client.get('connectedDevice', {}).get('name', client.get('deviceName', ''))) > 20 else '')
                ]
                client_table_data.append(row)

            client_table = Table(client_table_data)
            client_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(client_table)

        # System Health Section
        if ise_health or maglev_services or system_backup or system_updates:
            story.append(PageBreak())
            story.append(Paragraph("System Health Report", styles['Heading2']))
            story.append(Spacer(1, 12))

            # ISE Health Subsection
            if ise_health:
                story.append(Paragraph("Cisco ISE Health Status", styles['Heading3']))
                story.append(Spacer(1, 8))

                # ISE Summary
                total_ise_nodes = len(ise_health)
                available_nodes = len([n for n in ise_health if n.get('status') == 'AVAILABLE'])
                unavailable_nodes = total_ise_nodes - available_nodes

                ise_summary_data = [
                    ['ISE Health Summary', 'Count'],
                    ['Total ISE Nodes', str(total_ise_nodes)],
                    ['Available Nodes', str(available_nodes)],
                    ['Unavailable Nodes', str(unavailable_nodes)]
                ]

                ise_summary_table = Table(ise_summary_data)
                ise_summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))

                story.append(ise_summary_table)
                story.append(Spacer(1, 15))

                # ISE Details Table
                ise_table_data = [
                    ['FQDN', 'IP Address', 'Role', 'Status', 'Last Update']
                ]

                for node in ise_health:
                    last_update = node.get('lastUpdateTime', 'N/A')
                    if last_update != 'N/A' and isinstance(last_update, (int, float)):
                        try:
                            last_update = datetime.fromtimestamp(last_update / 1000).strftime('%Y-%m-%d %H:%M')
                        except:
                            last_update = 'N/A'

                    row = [
                        node.get('fqdn', 'N/A')[:25] + ('...' if len(node.get('fqdn', '')) > 25 else ''),
                        node.get('ipAddress', 'N/A'),
                        node.get('role', 'N/A'),
                        node.get('status', 'N/A'),
                        str(last_update)
                    ]
                    ise_table_data.append(row)

                ise_table = Table(ise_table_data)
                ise_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
                ]))

                story.append(ise_table)
                story.append(Spacer(1, 20))

            # Maglev Services Subsection
            if maglev_services:
                story.append(Paragraph("Maglev Services Status", styles['Heading3']))
                story.append(Spacer(1, 8))

                # Maglev Summary
                total_services = len(maglev_services)
                running_services = 0
                ready_services = 0

                for service in maglev_services:
                    if service.get('status') == 'running':
                        running_services += 1
                    if service.get('readyReplicas', 0) > 0:
                        ready_services += 1

                maglev_summary_data = [
                    ['Maglev Services Summary', 'Count'],
                    ['Total Services', str(total_services)],
                    ['Running Instances', str(running_services)],
                    ['Ready Instances', str(ready_services)]
                ]

                maglev_summary_table = Table(maglev_summary_data)
                maglev_summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))

                story.append(maglev_summary_table)
                story.append(Spacer(1, 15))

                # Note about detailed services
                note_text = f"Note: Showing summary for {total_services} Maglev services. Full service details available in system logs."
                story.append(Paragraph(note_text, styles['Normal']))
                story.append(Spacer(1, 20))

            # System Backup Subsection
            if system_backup:
                story.append(Paragraph("System Backup Information", styles['Heading3']))
                story.append(Spacer(1, 8))

                # Backup Summary
                total_backups = len(system_backup)
                successful_backups = len([b for b in system_backup if b.get('status') == 'SUCCESS'])
                failed_backups = total_backups - successful_backups

                backup_summary_data = [
                    ['Backup Summary', 'Count'],
                    ['Total Backups', str(total_backups)],
                    ['Successful Backups', str(successful_backups)],
                    ['Failed Backups', str(failed_backups)]
                ]

                backup_summary_table = Table(backup_summary_data)
                backup_summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))

                story.append(backup_summary_table)
                story.append(Spacer(1, 15))

                # Backup Details Table
                backup_table_data = [
                    ['Description', 'Status', 'Start Time', 'Size', 'Compatible']
                ]

                for backup in system_backup:
                    start_time = backup.get('start_time', 'N/A')
                    start_time_str = start_time
                    if start_time != 'N/A' and isinstance(start_time, (int, float)):
                        try:
                            start_time_str = datetime.fromtimestamp(start_time / 1000).strftime('%Y-%m-%d %H:%M')
                        except:
                            start_time_str = 'N/A'

                    backup_size = backup.get('backup_size', 'N/A')
                    backup_size_str = backup_size
                    if backup_size != 'N/A' and isinstance(backup_size, (int, float)):
                        backup_size_str = f"{backup_size / (1024*1024*1024):.2f} GB"

                    row = [
                        backup.get('description', 'N/A')[:25] + ('...' if len(backup.get('description', '')) > 25 else ''),
                        backup.get('status', 'N/A'),
                        start_time_str,
                        backup_size_str,
                        str(backup.get('compatible', 'N/A'))
                    ]
                    backup_table_data.append(row)

                backup_table = Table(backup_table_data)
                backup_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
                ]))

                story.append(backup_table)
                story.append(Spacer(1, 20))

            # System Updates Subsection
            if system_updates:
                story.append(Paragraph("System Update Information", styles['Heading3']))
                story.append(Spacer(1, 8))

                update_table_data = [
                    ['Update Information', 'Value'],
                    ['Latest Available Version', str(system_updates.get('latestAvailableVersion', 'N/A'))],
                    ['Update Package Status', str(system_updates.get('latestUpdatePackageStatus', 'N/A'))],
                    ['Status Message', str(system_updates.get('latestUpdatePackageStatusMessage', 'N/A'))]
                ]

                update_table = Table(update_table_data)
                update_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))

                story.append(update_table)

        # EoX Status Section
        if eox_status:
            story.append(PageBreak())
            story.append(Paragraph("End of Life/Support (EoX) Status", styles['Heading2']))
            story.append(Spacer(1, 12))

            # EoX Summary
            total_eox = len(eox_status)
            eol_devices = [d for d in eox_status if d.get('eoxDate') or d.get('eoLifeDate')]
            eos_devices = [d for d in eox_status if d.get('eoSupportDate') or d.get('endOfSupportDate')]
            
            eox_summary_data = [
                ['EoX Summary', 'Count'],
                ['Total Devices with EoX Data', str(total_eox)],
                ['Devices at/near End of Life', str(len(eol_devices))],
                ['Devices at/near End of Support', str(len(eos_devices))]
            ]

            eox_summary_table = Table(eox_summary_data)
            eox_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(eox_summary_table)
            story.append(Spacer(1, 20))

            # EoX Details Table
            eox_table_data = [
                ['Device Name', 'Product ID', 'EoL Date', 'EoS Date', 'Bulletin URL']
            ]

            for device in eox_status:
                device_name = device.get('deviceName') or device.get('hostname', 'N/A')
                product_id = device.get('productId') or device.get('pid', 'N/A')
                eol_date = device.get('eoxDate') or device.get('eoLifeDate', 'N/A')
                eos_date = device.get('eoSupportDate') or device.get('endOfSupportDate', 'N/A')
                bulletin_url = device.get('bulletinUrl') or device.get('url', 'N/A')
                
                # Truncate long values
                if isinstance(device_name, str) and len(device_name) > 30:
                    device_name = device_name[:27] + '...'
                if isinstance(bulletin_url, str) and len(bulletin_url) > 40:
                    bulletin_url = bulletin_url[:37] + '...'

                row = [
                    str(device_name),
                    str(product_id),
                    str(eol_date),
                    str(eos_date),
                    str(bulletin_url)
                ]
                eox_table_data.append(row)

            eox_table = Table(eox_table_data)
            eox_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(eox_table)

        # Compliance Status Section
        if non_compliant_devices:
            story.append(PageBreak())
            story.append(Paragraph("Device Compliance Status", styles['Heading2']))
            story.append(Spacer(1, 12))

            # Compliance Summary
            total_non_compliant = len(non_compliant_devices)
            
            # Group by compliance type
            compliance_types = {}
            for device in non_compliant_devices:
                comp_type = device.get('complianceType', 'UNKNOWN')
                compliance_types[comp_type] = compliance_types.get(comp_type, 0) + 1

            compliance_summary_data = [
                ['Compliance Summary', 'Count'],
                ['Total Non-Compliant Devices', str(total_non_compliant)]
            ]
            
            for comp_type, count in sorted(compliance_types.items()):
                compliance_summary_data.append([f'{comp_type} Issues', str(count)])

            compliance_summary_table = Table(compliance_summary_data)
            compliance_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(compliance_summary_table)
            story.append(Spacer(1, 20))

            # Compliance Details Table
            compliance_table_data = [
                ['Device Name', 'IP Address', 'Compliance Type', 'Status', 'Last Update']
            ]

            for device in non_compliant_devices:
                device_name = device.get('deviceName') or device.get('hostName', 'N/A')
                ip_address = device.get('ipAddress') or device.get('managementIpAddress', 'N/A')
                comp_type = device.get('complianceType', 'N/A')
                status = device.get('status', 'NON-COMPLIANT')
                last_update = device.get('lastUpdateTime', 'N/A')
                
                # Truncate long device names
                if isinstance(device_name, str) and len(device_name) > 30:
                    device_name = device_name[:27] + '...'
                
                # Format timestamp if available
                if isinstance(last_update, (int, float)):
                    try:
                        last_update = datetime.fromtimestamp(last_update/1000).strftime('%Y-%m-%d %H:%M')
                    except:
                        last_update = 'N/A'

                row = [
                    str(device_name),
                    str(ip_address),
                    str(comp_type),
                    str(status),
                    str(last_update)
                ]
                compliance_table_data.append(row)

            compliance_table = Table(compliance_table_data)
            compliance_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(compliance_table)

        # Golden Images Section
        if families_without_golden:
            story.append(PageBreak())
            story.append(Paragraph("Device Families Without Golden Images", styles['Heading2']))
            story.append(Spacer(1, 12))

            story.append(Paragraph(
                f"The following {len(families_without_golden)} device families are present in the inventory "
                "but do not have golden images assigned. Consider assigning golden images to ensure "
                "consistent software image management.",
                styles['Normal']
            ))
            story.append(Spacer(1, 12))

            # Golden Images Summary
            golden_summary_data = [
                ['Summary', 'Count'],
                ['Device Families Without Golden Images', str(len(families_without_golden))]
            ]

            golden_summary_table = Table(golden_summary_data)
            golden_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(golden_summary_table)
            story.append(Spacer(1, 20))

            # Device Families List
            families_table_data = [['Device Family']]
            
            for family in families_without_golden:
                families_table_data.append([str(family)])

            families_table = Table(families_table_data)
            families_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))

            story.append(families_table)

        # Build PDF
        doc.build(story)

        logging.info(f"Combined health PDF report generated: {filepath}")
        return filepath

