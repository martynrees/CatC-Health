"""
AI Health Analyzer Module

AI-powered health analysis using OpenAI and LangChain.
"""

import logging
from typing import Dict, Any
from datetime import datetime

try:
    from langchain_openai import ChatOpenAI
    from langchain.schema import HumanMessage, SystemMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False


class AIHealthAnalyzer:
    """AI-powered health analysis using OpenAI and LangChain"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the AI analyzer

        Args:
            config: AI configuration dictionary
        """
        self.config = config
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(f"{__name__}.AIHealthAnalyzer")
        logger.setLevel(logging.INFO)
        return logger

    def analyze_health_data(self, health_data: Dict[str, Any]) -> str:
        """
        Analyze health data using OpenAI and return a summary

        Args:
            health_data: Dictionary containing all health data from the monitoring

        Returns:
            Summary string or error message
        """
        if not LANGCHAIN_AVAILABLE:
            return "❌ AI Summary Error: LangChain dependencies not installed. Please install: pip install langchain langchain-openai"

        if not self.config.get("openai_api_key"):
            return "❌ AI Summary Error: The summary was not able to be processed as the API key was not provided."

        try:
            # Initialize OpenAI client with timeout
            llm = ChatOpenAI(
                model=self.config["model_name"],
                api_key=self.config["openai_api_key"],
                temperature=0.1,
                timeout=60,  # 60 second timeout for API calls
                max_retries=2  # Retry failed requests twice
            )

            # Prepare the health data summary for analysis
            data_summary = self._prepare_data_summary(health_data)

            # Create messages
            system_message = SystemMessage(content=self.config["system_prompt"])
            human_message = HumanMessage(content=f"""
Please analyze the following Cisco Catalyst Center health data and provide a concise summary with urgent call-outs:

{data_summary}

Please provide:
1. Overall network health status
2. Critical issues requiring immediate attention
3. Key recommendations for the network engineer
4. Any trends or patterns noticed

Keep the summary concise but comprehensive for quick decision making.
""")

            # Get AI response
            self.logger.info("Sending health data to OpenAI for analysis...")
            response = llm.invoke([system_message, human_message])

            summary = response.content.strip()
            self.logger.info("AI analysis completed successfully")
            return summary

        except Exception as e:
            error_msg = str(e).lower()
            if "quota" in error_msg or "rate limit" in error_msg:
                return "❌ AI Summary Error: The summary was not able to be processed as the API quota was exceeded."
            elif "api" in error_msg and ("unavailable" in error_msg or "connection" in error_msg):
                return "❌ AI Summary Error: The summary was not able to be processed as the API was not available."
            elif "timeout" in error_msg or "timed out" in error_msg:
                return "❌ AI Summary Error: The summary request timed out. The OpenAI API may be slow or unresponsive."
            else:
                self.logger.error(f"AI analysis failed: {e}")
                return f"❌ AI Summary Error: Failed to process health data analysis. Error: {str(e)}"

    def _prepare_data_summary(self, health_data: Dict[str, Any]) -> str:
        """
        Prepare a formatted summary of the health data for AI analysis

        Args:
            health_data: Raw health data dictionary

        Returns:
            Formatted string summary
        """
        summary_parts = []

        # Device Health Summary
        devices = health_data.get('all_devices', [])
        if devices:
            total_devices = len(devices)
            poor_devices = len([d for d in devices if d.get('overallHealth', 0) <= 3])
            fair_devices = len([d for d in devices if 3 < d.get('overallHealth', 0) <= 7])
            good_devices = len([d for d in devices if d.get('overallHealth', 0) > 7])

            summary_parts.append(f"""
DEVICE HEALTH SUMMARY:
- Total Devices: {total_devices}
- Poor Health (≤3): {poor_devices} ({(poor_devices/max(total_devices,1)*100):.1f}%)
- Fair Health (4-7): {fair_devices} ({(fair_devices/max(total_devices,1)*100):.1f}%)
- Good Health (>7): {good_devices} ({(good_devices/max(total_devices,1)*100):.1f}%)
""")

            # Add device details for poor health devices
            if poor_devices > 0:
                poor_device_details = []
                for device in devices:
                    if device.get('overallHealth', 0) <= 3:
                        poor_device_details.append(f"  - {device.get('name', 'Unknown')} (IP: {device.get('ipAddress', 'N/A')}, Health: {device.get('overallHealth', 'N/A')})")

                if poor_device_details:
                    summary_parts.append("CRITICAL DEVICES REQUIRING ATTENTION:")
                    summary_parts.extend(poor_device_details[:10])  # Limit to top 10
                    if len(poor_device_details) > 10:
                        summary_parts.append(f"  ... and {len(poor_device_details) - 10} more devices")

        # Issues Summary
        issues = health_data.get('issues', [])
        if issues:
            p1_issues = [i for i in issues if i.get('priority') == 'P1']
            p2_issues = [i for i in issues if i.get('priority') == 'P2']

            summary_parts.append(f"""
CRITICAL ISSUES SUMMARY:
- P1 (Critical) Issues: {len(p1_issues)}
- P2 (High Priority) Issues: {len(p2_issues)}
""")

            # Add critical issue details
            if p1_issues:
                summary_parts.append("P1 CRITICAL ISSUES:")
                for issue in p1_issues[:5]:  # Top 5 critical issues
                    summary_parts.append(f"  - {issue.get('name', 'Unknown Issue')}")

        # Fabric Health Summary
        fabric_health = health_data.get('fabric_health', [])
        if fabric_health:
            critical_sites = [s for s in fabric_health if s.get('goodHealthPercentage', 0) < 50]
            warning_sites = [s for s in fabric_health if 50 <= s.get('goodHealthPercentage', 0) < 80]

            summary_parts.append(f"""
SDA FABRIC HEALTH:
- Total Fabric Sites: {len(fabric_health)}
- Critical Sites (<50% health): {len(critical_sites)}
- Warning Sites (50-79% health): {len(warning_sites)}
""")

            if critical_sites:
                summary_parts.append("CRITICAL FABRIC SITES:")
                for site in critical_sites:
                    summary_parts.append(f"  - {site.get('name', 'Unknown Site')} ({site.get('goodHealthPercentage', 0):.1f}% health)")

        # Client Health Summary
        clients = health_data.get('clients', [])
        if clients:
            poor_clients = len([c for c in clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'POOR'])

            summary_parts.append(f"""
CLIENT HEALTH:
- Total Clients: {len(clients)}
- Poor Health Clients: {poor_clients}
""")

        # System Health Summary
        ise_health = health_data.get('ise_health', [])
        maglev_services = health_data.get('maglev_services', [])
        system_backup = health_data.get('system_backup', [])

        if ise_health or maglev_services or system_backup:
            available_ise = len([n for n in ise_health if n.get('status') == 'AVAILABLE'])
            running_services = len([s for s in maglev_services if s.get('status') == 'running'])
            successful_backups = len([b for b in system_backup if b.get('status') == 'SUCCESS'])

            summary_parts.append(f"""
SYSTEM HEALTH:
- ISE Nodes Available: {available_ise}/{len(ise_health)}
- Maglev Services Running: {running_services}/{len(maglev_services)}
- Successful Backups: {successful_backups}/{len(system_backup)}
""")

        return "\n".join(summary_parts)

    def _categorize_client_health(self, health_score: Any) -> str:
        """Categorize client health based on health score"""
        if not isinstance(health_score, (int, float)):
            return 'UNKNOWN'
        if health_score < 4:
            return 'POOR'
        elif health_score < 7:
            return 'FAIR'
        else:
            return 'GOOD'
