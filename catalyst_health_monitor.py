#!/usr/bin/env python3
"""
Cisco Catalyst Center Daily Health Monitor

Modular version using catc_health package.
"""

import sys
import logging
import argparse
from datetime import datetime
from dotenv import load_dotenv

# Import from our modular package
from catc_health import (
    CatalystCenterClient,
    AIHealthAnalyzer,
    NotificationManager,
    HealthReportGenerator,
    CATALYST_CENTER_CONFIG,
    AI_CONFIG,
    WEBEX_CONFIG,
    EMAIL_CONFIG,
    TEAMS_CONFIG,
    validate_config,
    categorize_health
)

def main():
    """Main function to run the health monitoring"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Cisco Catalyst Center Health Monitor with '
                    'Multi-Channel Notifications'
    )
    
    # AI analysis flag (independent from notifications)
    parser.add_argument('--ai-summary', action='store_true',
                       help='Enable AI-powered health analysis summary')
    
    # Notification channel flags (override .env settings)
    parser.add_argument(
        '--notify-email',
        action='store_true',
        help='Send notification via email (overrides .env setting)'
    )
    parser.add_argument(
        '--notify-webex',
        action='store_true',
        help='Send via Webex Teams (overrides .env setting)'
    )
    parser.add_argument(
        '--notify-teams',
        action='store_true',
        help='Send via MS Teams (overrides .env setting)'
    )
    parser.add_argument('--no-notifications', action='store_true',
                       help='Disable all notifications for this run')
    
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('catalyst_health_monitor.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

    try:
        # Load environment variables
        load_dotenv()

        # Validate configuration using new validation function
        is_valid, validation_errors = validate_config()
        if not is_valid:
            logging.error("Configuration validation failed:")
            for error in validation_errors:
                logging.error(f"  {error}")
            logging.error("\nPlease update your .env file with correct values.")
            logging.error("See .env.example for reference.")
            sys.exit(1)

        # Initialize client
        client = CatalystCenterClient(CATALYST_CENTER_CONFIG)

        # Authenticate
        if not client.authenticate():
            logging.error("Authentication failed. Exiting.")
            sys.exit(1)

        logging.info("Starting health data collection...")

        # Get timestamp for consistent naming
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Initialize all variables to ensure they exist
        devices = []
        assurance_issues = []
        intent_issues = []
        all_issues = []
        all_sites = []
        fabric_sites = []
        fabric_health = []
        applications = []
        clients = []
        ise_health = []
        maglev_services = []
        system_backup = []
        backup_history = []
        system_updates = {}

        # Collect device health data (only poor and fair health devices)
        logging.info("Collecting device health data...")
        try:
            # Alternative approach: Get all devices and filter for poor/fair health
            all_devices = client.get_device_health()

            # Filter for only poor and fair health devices (health score <= 7)
            devices = []
            for device in all_devices:
                health_score = device.get('overallHealth', 0)
                health_score = device.get('overallHealth', 0)
                is_poor_or_fair = (
                    isinstance(health_score, (int, float))
                    and health_score <= 7
                )
                if is_poor_or_fair:
                    devices.append(device)

            poor_count = len([
                d for d in devices
                if d.get('overallHealth', 0) <= 3
            ])
            fair_count = len([
                d for d in devices
                if 3 < d.get('overallHealth', 0) <= 7
            ])

            logging.info(
                f"Retrieved {len(all_devices)} total devices, "
                f"filtered to {len(devices)} poor/fair health devices"
            )
            logging.info(
                f"Breakdown: {poor_count} poor health, "
                f"{fair_count} fair health devices"
            )
        except Exception as e:
            logging.warning(f"Failed to collect device health data: {e}")
            devices = []
            all_devices = []

        # Collect assurance issues
        logging.info("Collecting assurance issues...")
        try:
            assurance_issues = client.get_assurance_issues()
            logging.info(f"Retrieved {len(assurance_issues)} assurance issues")
        except Exception as e:
            logging.warning(f"Failed to collect assurance issues: {e}")

        # Collect critical and high priority intent issues
        logging.info(
            "Collecting critical (P1) and high priority (P2) "
            "intent issues..."
        )
        try:
            p1_issues = client.get_intent_issues(
                priority="P1",
                issue_status="active"
            )
            p2_issues = client.get_intent_issues(
                priority="P2",
                issue_status="active"
            )
            intent_issues = p1_issues + p2_issues
            logging.info(
                f"Retrieved {len(p1_issues)} P1 and "
                f"{len(p2_issues)} P2 intent issues"
            )
        except Exception as e:
            logging.warning(f"Failed to collect intent issues: {e}")

        # Combine all issues for reporting
        all_issues = assurance_issues + intent_issues
        logging.info(f"Total issues for reporting: {len(all_issues)}")

        # Collect SDA fabric sites
        logging.info("Collecting SDA fabric sites...")
        try:
            fabric_sites = client.get_fabric_sites()
            logging.info(f"Retrieved {len(fabric_sites)} fabric sites")
        except Exception as e:
            logging.warning(f"Failed to collect fabric sites: {e}")

        # Collect all sites for site name mapping
        logging.info("Collecting all sites for site name mapping...")
        try:
            all_sites = client.get_sites()
            logging.info(f"Retrieved {len(all_sites)} sites for mapping")
        except Exception as e:
            logging.warning(f"Failed to collect sites: {e}")
            all_sites = []

        # Collect SDA fabric health
        logging.info("Collecting SDA fabric health...")
        try:
            fabric_health = client.get_fabric_site_health()
            logging.info(
                f"Retrieved fabric health data for "
                f"{len(fabric_health)} sites"
            )

            # Debug: Show sample data structure
            if fabric_health and len(fabric_health) > 0:
                sample_health = fabric_health[0]
                health_keys = list(sample_health.keys())
                logging.info(f"Fabric health sample keys: {health_keys}")

            if all_sites and len(all_sites) > 0:
                sample_site = all_sites[0]
                site_keys = list(sample_site.keys())
                logging.info(f"All sites sample keys: {site_keys}")

        except Exception as e:
            logging.warning(f"Failed to collect fabric health: {e}")

        # Collect application health (Poor and Fair applications)
        logging.info("Collecting application health...")
        try:
            poor_applications = client.get_application_health(
                application_health="POOR"
            )
            fair_applications = client.get_application_health(
                application_health="FAIR"
            )
            applications = poor_applications + fair_applications
            logging.info(
                f"Retrieved {len(applications)} applications "
                f"with Poor or Fair health"
            )
        except Exception as e:
            logging.warning(f"Failed to collect application health data: {e}")
            applications = []

        # Collect client health (Poor and Fair clients for both wired and wireless)
        logging.info("Collecting client health...")
        try:
            # Use Data API to get individual client records with detailed information
            logging.info("Using Data API for detailed client information...")
            all_clients = client.get_clients()
            # Filter for poor and fair health clients using shared utility function
            clients = [c for c in all_clients if categorize_health(c.get('health', {}).get('overallScore', 0)) in ['POOR', 'FAIR']]
            logging.info(f"Retrieved {len(clients)} clients with Poor or Fair health from Data API")
        except Exception as e:
            logging.warning(f"Failed to collect client health data: {e}")
            clients = []

        # Collect internal system health data
        logging.info("Collecting internal system health data...")

        # ISE Health
        try:
            ise_health = client.get_ise_health()
            logging.info(f"Retrieved ISE health data for {len(ise_health)} nodes")
        except Exception as e:
            logging.warning(f"Failed to collect ISE health data: {e}")
            ise_health = []

        # Maglev Services
        try:
            maglev_services = client.get_maglev_services()
            logging.info(f"Retrieved {len(maglev_services)} Maglev services")
        except Exception as e:
            logging.warning(f"Failed to collect Maglev services data: {e}")
            maglev_services = []

        # System Backup
        try:
            system_backup = client.get_system_backup()
            logging.info(f"Retrieved {len(system_backup)} system backups")
        except Exception as e:
            logging.warning(f"Failed to collect system backup data: {e}")
            system_backup = []

        # Backup History
        try:
            backup_history = client.get_backup_history()
            logging.info(f"Retrieved backup history with {len(backup_history)} records")
        except Exception as e:
            logging.warning(f"Failed to collect backup history data: {e}")
            backup_history = []

        # System Updates
        try:
            system_updates = client.get_system_updates()
            logging.info("Retrieved system update information")
        except Exception as e:
            logging.warning(f"Failed to collect system update data: {e}")
            system_updates = {}

        # Collect EoX (End of Life/Support) status
        logging.info("Collecting End of Life/Support (EoX) status...")
        try:
            eox_status = client.get_eox_status()
            logging.info(f"Retrieved EoX status for {len(eox_status)} devices")
        except Exception as e:
            logging.warning(f"Failed to collect EoX status: {e}")
            eox_status = []

        # Collect compliance details
        logging.info("Collecting device compliance details...")
        try:
            all_compliance = client.get_compliance_details()
            # Filter for non-compliant devices only
            non_compliant_devices = [c for c in all_compliance if c.get('status') != 'COMPLIANT']
            logging.info(f"Retrieved {len(all_compliance)} compliance records, {len(non_compliant_devices)} non-compliant")
        except Exception as e:
            logging.warning(f"Failed to collect compliance details: {e}")
            all_compliance = []
            non_compliant_devices = []

        # Collect golden images and device families
        logging.info("Collecting golden images and device families...")
        try:
            golden_images = client.get_golden_images()
            device_families = client.get_device_families()
            
            # Extract device families from inventory (devices in use)
            inventory_families = set()
            for device in all_devices if 'all_devices' in locals() else devices:
                family = device.get('family') or device.get('platformId') or device.get('series')
                if family:
                    inventory_families.add(family)
            
            # Get families covered by golden images
            golden_families = set()
            for image in golden_images:
                family = image.get('family') or image.get('deviceFamily')
                if family:
                    golden_families.add(family)
            
            # Find families in inventory without golden images
            families_without_golden = sorted(inventory_families - golden_families)
            
            logging.info(f"Retrieved {len(golden_images)} golden images")
            logging.info(f"Found {len(inventory_families)} device families in inventory")
            logging.info(f"Found {len(families_without_golden)} families without golden images")
            
        except Exception as e:
            logging.warning(f"Failed to collect golden image data: {e}")
            golden_images = []
            families_without_golden = []

        # Compile all health data for AI analysis
        health_data = {
            'all_devices': all_devices if 'all_devices' in locals() else devices,
            'devices': devices,
            'issues': all_issues,
            'fabric_health': fabric_health,
            'applications': applications,
            'clients': clients,
            'ise_health': ise_health,
            'maglev_services': maglev_services,
            'system_backup': system_backup,
            'backup_history': backup_history,
            'system_updates': system_updates,
            'eox_status': eox_status,
            'compliance': all_compliance,
            'non_compliant_devices': non_compliant_devices,
            'golden_images': golden_images,
            'families_without_golden': families_without_golden,
            'timestamp': datetime.now().isoformat()
        }

        # Generate reports
        report_generator = HealthReportGenerator()

        # Generate only the combined report (includes all health data)
        combined_report = report_generator.generate_combined_pdf(
            devices, all_devices, all_issues, fabric_sites, fabric_health, all_sites,
            applications, clients, ise_health, maglev_services, system_backup,
            backup_history, system_updates, eox_status, non_compliant_devices, 
            families_without_golden, timestamp
        )

        logging.info("Health monitoring completed successfully!")
        logging.info(f"Report generated:")
        logging.info(f"  - Comprehensive Health Report: {combined_report}")

        # Determine CLI overrides for notification channels
        cli_overrides = {}
        if args.no_notifications:
            # Disable all channels
            cli_overrides = {'email': False, 'webex': False, 'teams': False}
        else:
            # Apply individual channel overrides
            if args.notify_email:
                cli_overrides['email'] = True
            if args.notify_webex:
                cli_overrides['webex'] = True
            if args.notify_teams:
                cli_overrides['teams'] = True
        
        # Initialize notification manager
        notification_manager = NotificationManager(EMAIL_CONFIG, WEBEX_CONFIG, TEAMS_CONFIG)
        
        # Determine which channels are enabled
        enabled_channels = notification_manager.get_enabled_channels(cli_overrides)
        
        # Determine if we need AI summary
        need_ai_summary = args.ai_summary or len(enabled_channels) > 0
        
        # Generate AI summary if needed
        ai_summary = None
        if need_ai_summary:
            logging.info("Generating AI-powered health analysis...")
            try:
                ai_analyzer = AIHealthAnalyzer(AI_CONFIG)
                ai_summary = ai_analyzer.analyze_health_data(health_data)
                
                if args.ai_summary:
                    # Print AI summary to console if explicitly requested
                    print("\n" + "="*70)
                    print("🤖 AI HEALTH ANALYSIS SUMMARY")
                    print("="*70)
                    print(ai_summary)
                    print("="*70)
            except Exception as e:
                logging.warning(f"Failed to generate AI summary: {e}")
                ai_summary = None
        
        # Send notifications if channels are enabled
        if enabled_channels:
            # Prepare notification message
            if ai_summary:
                notification_message = ai_summary
            else:
                # Create basic summary if no AI
                notification_message = _create_basic_summary(health_data, devices, all_issues)
            
            # Send to all enabled channels
            logging.info(f"Sending notifications to {len(enabled_channels)} channel(s)...")
            results = notification_manager.send_notifications(
                message=notification_message,
                pdf_filepath=combined_report,
                enabled_channels=enabled_channels
            )
            
            # Report results
            successful = sum(1 for success in results.values() if success)
            if successful > 0:
                print(f"\n📧 Notifications sent successfully to {successful}/{len(results)} channel(s)")
                for channel, success in results.items():
                    status = "✅" if success else "❌"
                    print(f"   {status} {channel.capitalize()}")
            else:
                print("\n⚠️  All notification channels failed. Check logs for details.")
        elif args.ai_summary or any([args.notify_email, args.notify_webex, args.notify_teams]):
            # User requested notifications but none are configured
            print("\n⚠️  No notification channels are configured. Check your .env file.")
            print("     To enable notifications, set:")
            print("       ENABLE_EMAIL_NOTIFICATIONS=true  (and configure SMTP settings)")
            print("       ENABLE_WEBEX_NOTIFICATIONS=true  (and configure bot token)")
            print("       ENABLE_TEAMS_NOTIFICATIONS=true  (and configure webhook URL)")

        # Print summary
        print("\n" + "="*60)
        print("CATALYST CENTER HEALTH MONITORING SUMMARY")
        print("="*60)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Devices: {len(devices)}")
        print(f"Total Issues: {len(all_issues)} (Assurance: {len(assurance_issues)}, Intent P1/P2: {len(intent_issues)})")
        
        # Print device breakdown by health status
        poor_count = len([d for d in devices if categorize_health(d.get('overallHealth', 0)) == 'POOR'])
        fair_count = len([d for d in devices if categorize_health(d.get('overallHealth', 0)) == 'FAIR'])
        good_count = len([d for d in devices if categorize_health(d.get('overallHealth', 0)) == 'GOOD'])
        print(f"\nDevice Health Breakdown:")
        print(f"  🔴 Poor:  {poor_count} devices")
        print(f"  🟡 Fair:  {fair_count} devices")
        print(f"  🟢 Good:  {good_count} devices")
        print(f"Total SDA Fabric Sites: {len(fabric_sites)}")

        # Device health breakdown
        if devices:
            poor_count = len([d for d in devices if d.get('overallHealth', 0) <= 3])
            fair_count = len([d for d in devices if 3 < d.get('overallHealth', 0) <= 7])
            good_count = len([d for d in devices if d.get('overallHealth', 0) > 7])

            print(f"\nDevice Health Breakdown:")
            print(f"  Poor Health (≤3): {poor_count}")
            print(f"  Fair Health (4-7): {fair_count}")
            print(f"  Good Health (>7): {good_count}")

        # Issues breakdown
        if all_issues:
            p1_count = len([i for i in all_issues if i.get('priority') == 'P1'])
            p2_count = len([i for i in all_issues if i.get('priority') == 'P2'])
            p3_count = len([i for i in all_issues if i.get('priority') == 'P3'])
            p4_count = len([i for i in all_issues if i.get('priority') == 'P4'])

            print(f"\nIssues Breakdown by Priority:")
            print(f"  P1 (Critical): {p1_count}")
            print(f"  P2 (High): {p2_count}")
            print(f"  P3 (Medium): {p3_count}")
            print(f"  P4 (Low): {p4_count}")

        # SDA Fabric breakdown
        if fabric_health:
            healthy_fabric_count = len([s for s in fabric_health if s.get('goodHealthPercentage', 0) >= 80])
            warning_fabric_count = len([s for s in fabric_health if 50 <= s.get('goodHealthPercentage', 0) < 80])
            critical_fabric_count = len([s for s in fabric_health if s.get('goodHealthPercentage', 0) < 50])

            print(f"\nSDA Fabric Health Breakdown:")
            print(f"  Healthy Sites (≥80%): {healthy_fabric_count}")
            print(f"  Warning Sites (50-79%): {warning_fabric_count}")
            print(f"  Critical Sites (<50%): {critical_fabric_count}")

        # Client Health breakdown
        if clients:
            # For Intent API responses
            if clients and hasattr(clients[0], 'get') and 'scoreCategory' in str(clients[0]):
                poor_client_count = len([c for c in clients if c.get('scoreCategory') == 'POOR'])
                fair_client_count = len([c for c in clients if c.get('scoreCategory') == 'FAIR'])
                good_client_count = len([c for c in clients if c.get('scoreCategory') == 'GOOD'])

                # Separate wired and wireless counts
                wired_poor = len([c for c in clients if c.get('scoreCategory') == 'POOR' and c.get('connectedDevice', {}).get('connectionStatus') == 'WIRED'])
                wired_fair = len([c for c in clients if c.get('scoreCategory') == 'FAIR' and c.get('connectedDevice', {}).get('connectionStatus') == 'WIRED'])
                wireless_poor = len([c for c in clients if c.get('scoreCategory') == 'POOR' and c.get('connectedDevice', {}).get('connectionStatus') == 'WIRELESS'])
                wireless_fair = len([c for c in clients if c.get('scoreCategory') == 'FAIR' and c.get('connectedDevice', {}).get('connectionStatus') == 'WIRELESS'])
            else:
                # For Data API responses - categorize by health score
                # Use centralized categorize_health from utils
                poor_clients = [
                    c for c in clients
                    if categorize_health(
                        c.get('health', {}).get('overallScore', 0)
                    ) == 'POOR'
                ]
                fair_clients = [
                    c for c in clients
                    if categorize_health(
                        c.get('health', {}).get('overallScore', 0)
                    ) == 'FAIR'
                ]
                good_clients = [
                    c for c in clients
                    if categorize_health(
                        c.get('health', {}).get('overallScore', 0)
                    ) == 'GOOD'
                ]
                
                poor_client_count = len(poor_clients)
                fair_client_count = len(fair_clients)
                good_client_count = len(good_clients)

                # Separate wired and wireless
                wired_poor = len([
                    c for c in poor_clients
                    if c.get('type', '').upper() == 'WIRED'
                ])
                wired_fair = len([
                    c for c in fair_clients
                    if c.get('type', '').upper() == 'WIRED'
                ])
                wireless_poor = len([
                    c for c in poor_clients
                    if c.get('type', '').upper() == 'WIRELESS'
                ])
                wireless_fair = len([
                    c for c in fair_clients
                    if c.get('type', '').upper() == 'WIRELESS'
                ])

            print(f"\nClient Health Breakdown:")
            print(f"  Total Poor Health: {poor_client_count} (Wired: {wired_poor}, Wireless: {wireless_poor})")
            print(f"  Total Fair Health: {fair_client_count} (Wired: {wired_fair}, Wireless: {wireless_fair})")
            print(f"  Total Good Health: {good_client_count}")

        # System Health breakdown
        system_status = "Unknown"
        if ise_health and len(ise_health) > 0:
            ise_nodes = ise_health[0].get('nodeCount', 0) if isinstance(ise_health, list) else ise_health.get('nodeCount', 0)
            if maglev_services:
                running_services = len([s for s in maglev_services if s.get('status') == 'running'])
                total_services = len(maglev_services)
                service_health = (running_services / total_services * 100) if total_services > 0 else 0
                if service_health >= 90:
                    system_status = "Healthy"
                elif service_health >= 75:
                    system_status = "Warning"
                else:
                    system_status = "Critical"

            print(f"\nSystem Health Summary:")
            print(f"  ISE Integration: {ise_nodes} nodes available")
            if maglev_services:
                running_services = len([s for s in maglev_services if s.get('status') == 'running'])
                total_services = len(maglev_services)
                service_health = (running_services / total_services * 100) if total_services > 0 else 0
                print(f"  System Services: {running_services}/{total_services} running ({service_health:.1f}%)")
            if system_backup:
                backup_count = len(system_backup) if isinstance(system_backup, list) else 1
                print(f"  System Backups: {backup_count} available")
            print(f"  Overall System Status: {system_status}")

        print(f"\nReports Generated:")
        print(f"  📊 Comprehensive Health Report: {combined_report}")

        # Show notification status
        if enabled_channels:
            print(f"\n  📧 Notifications:")
            for channel in enabled_channels:
                status = "✅ Sent" if results.get(channel) else "❌ Failed"
                print(f"     {channel.capitalize()}: {status}")
        
        if args.ai_summary and ai_summary:
            print(f"  🤖 AI Analysis: ✅ Completed")

        print("="*60)

    except KeyboardInterrupt:
        logging.info("Script interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        sys.exit(1)


def _create_basic_summary(health_data: dict, devices: list, issues: list) -> str:
    """
    Create a basic health summary when AI is not available.
    
    Args:
        health_data: Dictionary of collected health data
        devices: List of devices
        issues: List of issues
        
    Returns:
        Formatted basic summary text
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Count devices by health
    poor_devices = [d for d in devices if categorize_health(d.get('overallHealth', 0)) == 'POOR']
    fair_devices = [d for d in devices if categorize_health(d.get('overallHealth', 0)) == 'FAIR']
    good_devices = [d for d in devices if categorize_health(d.get('overallHealth', 0)) == 'GOOD']
    
    # Count critical issues (P1/P2)
    critical_issues = [i for i in issues if i.get('priority') in ['P1', 'P2']]
    
    summary = f"""
**Cisco Catalyst Center Health Report**
Generated: {timestamp}

**DEVICE HEALTH SUMMARY**
• Total Devices: {len(devices)}
• Poor Health: {len(poor_devices)} devices
• Fair Health: {len(fair_devices)} devices  
• Good Health: {len(good_devices)} devices

**ISSUE SUMMARY**
• Total Issues: {len(issues)}
• Critical Issues (P1/P2): {len(critical_issues)}

**SYSTEM HEALTH**
• ISE Nodes: {len(health_data.get('ise_health', []))}
• SDA Fabric Sites: {len(health_data.get('sda_health', []))}
• Client Issues: {len(health_data.get('clients', []))}

"""
    
    # Add top critical issues if any
    if critical_issues:
        summary += "**TOP CRITICAL ISSUES:**\n"
        for issue in critical_issues[:5]:
            summary += f"• {issue.get('name', 'Unknown')}\n"
    
    summary += "\n*For detailed analysis, please review the attached PDF report.*"
    
    return summary.strip()


if __name__ == "__main__":
    main()
