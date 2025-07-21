#!/usr/bin/env python3
"""
Cisco Catalyst Center Daily Health Monitor

This script connects to Cisco Catalyst Center and generates daily health reports
for network devices and assurance issues.
"""

import os
import sys
import json
import base64
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import requests
import urllib3
from dotenv import load_dotenv
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# AI and Webex imports (optional dependencies)
try:
    from langchain_openai import ChatOpenAI
    from langchain.schema import HumanMessage, SystemMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

try:
    from webexteamssdk import WebexTeamsAPI
    WEBEX_AVAILABLE = True
except ImportError:
    WEBEX_AVAILABLE = False

# Load environment variables
load_dotenv()

# Suppress InsecureRequestWarning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
CATALYST_CENTER_CONFIG = {
    "base_url": os.getenv("CATALYST_CENTER_URL", "https://your-catalyst-center.example.com"),
    "username": os.getenv("CATALYST_CENTER_USERNAME", "your_username"),
    "password": os.getenv("CATALYST_CENTER_PASSWORD", "your_password"),
    "verify_ssl": os.getenv("VERIFY_SSL", "false").lower() == "true",
    "timeout": int(os.getenv("REQUEST_TIMEOUT", "30"))
}

# AI and Webex Configuration
AI_CONFIG = {
    "openai_api_key": os.getenv("OPENAI_API_KEY"),
    "webex_token": os.getenv("WEBEX_BOT_TOKEN"),
    "webex_space_id": os.getenv("WEBEX_SPACE_ID"),
    "model_name": "gpt-4.1-mini",  # Updated to the correct model name
    "system_prompt": ("You are an expert in Cisco Catalyst Center, and you have received the daily health check PDF that you need to analyse and provide a short summary on. "
                     "You should identify any urgent call outs and include them so that the network engineer can quickly understand any actionable items")
}

# API Endpoints
API_ENDPOINTS = {
    "auth": "/dna/system/api/v1/auth/token",
    "device_health": "/dna/intent/api/v1/device-health",
    "network_devices": "/dna/data/api/v1/networkDevices",
    "assurance_issues": "/dna/data/api/v1/assuranceIssues",
    "intent_issues": "/dna/intent/api/v1/issues",
    "sites": "/dna/intent/api/v1/sites",
    "fabric_sites": "/dna/intent/api/v1/sda/fabricSites",
    "fabric_site_health": "/dna/data/api/v1/fabricSiteHealthSummaries",
    "application_health": "/dna/intent/api/v1/application-health",
    "network_applications": "/dna/data/api/v1/networkApplications",
    "client_health": "/dna/intent/api/v1/client-health",
    "clients": "/dna/data/api/v1/clients",
    # Internal API Endpoints
    "ise_health": "/api/v1/system/health/cisco-ise",
    "maglev_services": "/api/system/v1/maglev/services/summary",
    "system_backup": "/api/system/v1/maglev/backup",
    "backup_history": "/api/system/v1/maglev/backup/history",
    "system_updates": "/api/system/v1/systemupdater/common/availabe_update_info"
}

# Health score mapping for filtering
HEALTH_FILTERS = {
    "poor": "POOR",
    "fair": "FAIR",
    "good": "GOOD"
}

class CatalystCenterClient:
    """Client for interacting with Cisco Catalyst Center APIs"""

    def __init__(self, config: Dict[str, Any]):
        self.base_url = config["base_url"].rstrip("/")
        self.username = config["username"]
        self.password = config["password"]
        self.verify_ssl = config["verify_ssl"]
        self.timeout = config["timeout"]
        self.token = None
        self.session = requests.Session()

        # Setup logging
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)

        # Create console handler
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)

        # Add handler to logger
        if not logger.handlers:
            logger.addHandler(handler)

        return logger

    def authenticate(self) -> bool:
        """Authenticate with Catalyst Center and get access token"""
        url = f"{self.base_url}{API_ENDPOINTS['auth']}"

        # Encode credentials for basic auth
        import base64
        credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {credentials}"
        }

        try:
            self.logger.info("Authenticating with Catalyst Center...")
            response = self.session.post(
                url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            token_data = response.json()
            self.token = token_data.get("Token")

            if self.token:
                self.logger.info("Authentication successful")
                # Set default headers for future requests
                self.session.headers.update({
                    "Content-Type": "application/json",
                    "X-Auth-Token": self.token
                })
                return True
            else:
                self.logger.error("No token received in authentication response")
                return False

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Authentication failed: {e}")
            return False

    def get_device_health(self, health_filter: Optional[str] = None,
                         device_role: Optional[str] = None,
                         site_id: Optional[str] = None,
                         limit: int = 500) -> List[Dict]:
        """
        Get device health information using the Intent API

        Args:
            health_filter: Filter by health (POOR, FAIR, GOOD)
            device_role: Filter by device role (CORE, ACCESS, DISTRIBUTION, ROUTER, WLC, AP)
            site_id: Filter by site UUID
            limit: Maximum number of devices to return

        Returns:
            List of device health data
        """
        url = f"{self.base_url}{API_ENDPOINTS['device_health']}"

        params = {"limit": str(limit)}
        if health_filter:
            params["health"] = health_filter
        if device_role:
            params["deviceRole"] = device_role
        if site_id:
            params["siteId"] = site_id

        try:
            self.logger.info(f"Fetching device health data with filters: {params}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            devices = data.get("response", [])
            self.logger.info(f"Retrieved {len(devices)} devices")
            return devices

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get device health: {e}")
            return []

    def get_network_devices_with_health(self, health_scores: Optional[List[str]] = None,
                                      site_hierarchy: Optional[str] = None,
                                      limit: int = 500) -> List[Dict]:
        """
        Get network devices with health score filtering using Data API

        Args:
            health_scores: List of health scores to filter by (poor, fair, good)
            site_hierarchy: Site hierarchy filter
            limit: Maximum number of devices to return

        Returns:
            List of network device data
        """
        url = f"{self.base_url}{API_ENDPOINTS['network_devices']}"

        params = {"limit": str(limit)}
        if health_scores:
            for health in health_scores:
                params["healthScore"] = health
        if site_hierarchy:
            params["siteHierarchy"] = site_hierarchy

        try:
            self.logger.info(f"Fetching network devices with health filters: {params}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            devices = data.get("response", [])
            self.logger.info(f"Retrieved {len(devices)} network devices")
            return devices

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get network devices: {e}")
            return []

    def get_assurance_issues(self, severity: Optional[str] = None,
                           category: Optional[str] = None,
                           limit: int = 500) -> List[Dict]:
        """
        Get assurance issues

        Args:
            severity: Filter by severity (P1, P2, P3, P4)
            category: Filter by issue category
            limit: Maximum number of issues to return

        Returns:
            List of assurance issues
        """
        url = f"{self.base_url}{API_ENDPOINTS['assurance_issues']}"

        params = {"limit": str(limit)}
        if severity:
            params["severity"] = severity
        if category:
            params["category"] = category

        try:
            self.logger.info(f"Fetching assurance issues with filters: {params}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            issues = data.get("response", [])
            self.logger.info(f"Retrieved {len(issues)} issues")
            return issues

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get assurance issues: {e}")
            return []

    def get_intent_issues(self, priority: Optional[str] = None,
                         issue_status: Optional[str] = None,
                         limit: int = 500) -> List[Dict]:
        """
        Get issues using Intent API

        Args:
            priority: Filter by priority (P1, P2, P3, P4)
            issue_status: Filter by issue status (active, resolved, etc.)
            limit: Maximum number of issues to return

        Returns:
            List of intent issues
        """
        url = f"{self.base_url}{API_ENDPOINTS['intent_issues']}"

        params = {"limit": str(limit)}
        if priority:
            params["priority"] = priority
        if issue_status:
            params["issueStatus"] = issue_status

        try:
            self.logger.info(f"Fetching intent issues with filters: {params}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            issues = data.get("response", [])
            self.logger.info(f"Retrieved {len(issues)} intent issues")
            return issues

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get intent issues: {e}")
            return []

    def get_fabric_sites(self, limit: int = 500) -> List[Dict]:
        """
        Get SDA fabric sites

        Args:
            limit: Maximum number of fabric sites to return

        Returns:
            List of fabric sites data
        """
        url = f"{self.base_url}{API_ENDPOINTS['fabric_sites']}"

        params = {"limit": str(limit)}

        try:
            self.logger.info(f"Fetching fabric sites data with limit: {limit}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            sites = data.get("response", [])
            self.logger.info(f"Retrieved {len(sites)} fabric sites")
            return sites

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get fabric sites: {e}")
            return []

    def get_sites(self, limit: int = 500) -> List[Dict]:
        """
        Get all sites information

        Args:
            limit: Maximum number of sites to return

        Returns:
            List of sites data
        """
        url = f"{self.base_url}{API_ENDPOINTS['sites']}"

        params = {"limit": str(limit)}

        try:
            self.logger.info(f"Fetching sites data with limit: {limit}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            sites = data.get("response", [])
            self.logger.info(f"Retrieved {len(sites)} sites")
            return sites

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get sites: {e}")
            return []

    def get_site_by_id(self, site_id: str) -> Dict:
        """
        Get specific site information by ID

        Args:
            site_id: Site UUID

        Returns:
            Site data
        """
        url = f"{self.base_url}{API_ENDPOINTS['sites']}/{site_id}"

        try:
            self.logger.info(f"Fetching site data for ID: {site_id}")
            response = self.session.get(
                url,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            site_data = data.get("response", {})
            self.logger.info(f"Retrieved site data for {site_id}")
            return site_data

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get site by ID {site_id}: {e}")
            return {}

    def get_fabric_site_health(self, start_time: Optional[int] = None,
                               end_time: Optional[int] = None,
                               limit: int = 500) -> List[Dict]:
        """
        Get SDA fabric site health summaries

        Args:
            start_time: Start time in UNIX epoch milliseconds
            end_time: End time in UNIX epoch milliseconds
            limit: Maximum number of fabric site health records to return

        Returns:
            List of fabric site health summaries
        """
        url = f"{self.base_url}{API_ENDPOINTS['fabric_site_health']}"

        params = {"limit": str(limit)}
        if start_time:
            params["startTime"] = str(start_time)
        if end_time:
            params["endTime"] = str(end_time)

        try:
            self.logger.info(f"Fetching fabric site health data with params: {params}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            health_data = data.get("response", [])
            self.logger.info(f"Retrieved fabric site health data for {len(health_data)} sites")
            return health_data

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get fabric site health: {e}")
            return []

    def get_application_health(self, site_id: Optional[str] = None,
                              application_health: Optional[str] = None,
                              start_time: Optional[int] = None,
                              end_time: Optional[int] = None,
                              limit: int = 500) -> List[Dict]:
        """
        Get application health using Intent API

        Args:
            site_id: Site UUID to filter applications
            application_health: Application health category (POOR, FAIR, GOOD)
            start_time: Start time in UNIX epoch milliseconds
            end_time: End time in UNIX epoch milliseconds
            limit: Maximum number of applications to return

        Returns:
            List of application health data
        """
        url = f"{self.base_url}{API_ENDPOINTS['application_health']}"

        params = {"limit": str(limit)}
        if site_id:
            params["siteId"] = site_id
        if application_health:
            params["applicationHealth"] = application_health
        if start_time:
            params["startTime"] = str(start_time)
        if end_time:
            params["endTime"] = str(end_time)

        try:
            self.logger.info(f"Fetching application health data with params: {params}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            applications = data.get("response", [])
            self.logger.info(f"Retrieved {len(applications)} applications")
            return applications

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get application health: {e}")
            return []

    def get_network_applications(self, site_id: str,
                                start_time: Optional[int] = None,
                                end_time: Optional[int] = None,
                                limit: int = 500) -> List[Dict]:
        """
        Get network applications with detailed health metrics using Data API

        Args:
            site_id: Site UUID (required for this API)
            start_time: Start time in UNIX epoch milliseconds
            end_time: End time in UNIX epoch milliseconds
            limit: Maximum number of applications to return

        Returns:
            List of network applications with health metrics
        """
        url = f"{self.base_url}{API_ENDPOINTS['network_applications']}"

        params = {
            "siteId": site_id,
            "limit": str(limit),
            "attribute": "healthScore,applicationName,usage,throughput,packetLossPercent,networkLatency"
        }
        if start_time:
            params["startTime"] = str(start_time)
        if end_time:
            params["endTime"] = str(end_time)

        try:
            self.logger.info(f"Fetching network applications data with params: {params}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            applications = data.get("response", [])
            self.logger.info(f"Retrieved {len(applications)} network applications")
            return applications

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get network applications: {e}")
            return []

    def get_client_health(self, site_id: Optional[str] = None,
                         connection_type: Optional[str] = None,
                         health_score: Optional[str] = None,
                         limit: int = 500) -> List[Dict]:
        """
        Get client health using Intent API

        Args:
            site_id: Site UUID to filter clients
            connection_type: Connection type (wired, wireless)
            health_score: Health score filter (poor, fair, good)
            limit: Maximum number of clients to return

        Returns:
            List of client health data
        """
        url = f"{self.base_url}{API_ENDPOINTS['client_health']}"

        params = {"limit": str(limit)}
        if site_id:
            params["siteId"] = site_id
        if connection_type:
            params["connectionType"] = connection_type
        if health_score:
            params["healthScore"] = health_score

        try:
            self.logger.info(f"Fetching client health data with params: {params}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            clients = data.get("response", [])
            self.logger.info(f"Retrieved {len(clients)} clients")
            return clients

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get client health: {e}")
            return []

    def get_clients(self, site_hierarchy: Optional[str] = None,
                   connection_type: Optional[str] = None,
                   limit: int = 500) -> List[Dict]:
        """
        Get clients with detailed information using Data API

        Args:
            site_hierarchy: Site hierarchy filter
            connection_type: Connection type (wired, wireless)
            limit: Maximum number of clients to return

        Returns:
            List of client data with health information
        """
        url = f"{self.base_url}{API_ENDPOINTS['clients']}"

        params = {
            "limit": str(limit)
        }
        if site_hierarchy:
            params["siteHierarchy"] = site_hierarchy
        if connection_type:
            params["connectionType"] = connection_type

        try:
            self.logger.info(f"Fetching clients data with params: {params}")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            clients = data.get("response", [])
            self.logger.info(f"Retrieved {len(clients)} clients with detailed information")
            return clients

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get clients: {e}")
            return []

    def get_ise_health(self, limit: int = 500) -> List[Dict]:
        """
        Get Cisco ISE health status

        Args:
            limit: Maximum number of ISE nodes to return

        Returns:
            List of ISE health data
        """
        url = f"{self.base_url}{API_ENDPOINTS['ise_health']}"

        params = {"limit": str(limit)}

        try:
            self.logger.info("Fetching Cisco ISE health status")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            ise_nodes = data.get("response", [])
            self.logger.info(f"Retrieved ISE health data for {len(ise_nodes)} nodes")
            return ise_nodes

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get ISE health: {e}")
            return []

    def get_maglev_services(self, limit: int = 500) -> List[Dict]:
        """
        Get Maglev services summary

        Args:
            limit: Maximum number of services to return

        Returns:
            List of Maglev services data
        """
        url = f"{self.base_url}{API_ENDPOINTS['maglev_services']}"

        params = {"limit": str(limit)}

        try:
            self.logger.info("Fetching Maglev services summary")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            services = data.get("response", [])
            self.logger.info(f"Retrieved {len(services)} Maglev services")
            return services

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Maglev services: {e}")
            return []

    def get_system_backup(self, limit: int = 500) -> List[Dict]:
        """
        Get system backup information

        Args:
            limit: Maximum number of backups to return

        Returns:
            List of system backup data
        """
        url = f"{self.base_url}{API_ENDPOINTS['system_backup']}"

        params = {"limit": str(limit)}

        try:
            self.logger.info("Fetching system backup information")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            backups = data.get("response", [])
            self.logger.info(f"Retrieved {len(backups)} system backups")
            return backups

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get system backup: {e}")
            return []

    def get_backup_history(self, limit: int = 500) -> List[Dict]:
        """
        Get backup history

        Args:
            limit: Maximum number of backup history records to return

        Returns:
            List of backup history data
        """
        url = f"{self.base_url}{API_ENDPOINTS['backup_history']}"

        params = {"limit": str(limit)}

        try:
            self.logger.info("Fetching backup history")
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            history = data.get("response", [])
            self.logger.info(f"Retrieved backup history with {len(history)} records")
            return history

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get backup history: {e}")
            return []

    def get_system_updates(self) -> Dict:
        """
        Get system update information

        Returns:
            Dictionary containing system update data
        """
        url = f"{self.base_url}{API_ENDPOINTS['system_updates']}"

        try:
            self.logger.info("Fetching system update information")
            response = self.session.get(
                url,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            update_info = data.get("response", {})
            self.logger.info("Retrieved system update information")
            return update_info

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get system updates: {e}")
            return {}

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
            # Initialize OpenAI client
            llm = ChatOpenAI(
                model=self.config["model_name"],
                api_key=self.config["openai_api_key"],
                temperature=0.1
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

class WebexNotifier:
    """Webex Teams notification service"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Webex notifier

        Args:
            config: AI configuration dictionary containing Webex settings
        """
        self.config = config
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(f"{__name__}.WebexNotifier")
        logger.setLevel(logging.INFO)
        return logger

    def send_health_report(self, summary: str, pdf_filepath: str) -> bool:
        """
        Send health report summary and PDF to Webex space

        Args:
            summary: AI-generated summary text
            pdf_filepath: Path to the PDF report file

        Returns:
            True if successful, False otherwise
        """
        if not WEBEX_AVAILABLE:
            self.logger.error("Webex SDK not available. Please install: pip install webexteamssdk")
            return False

        if not self.config.get("webex_token"):
            self.logger.error("Webex bot token not provided in configuration")
            return False

        if not self.config.get("webex_space_id"):
            self.logger.error("Webex space ID not provided in configuration")
            return False

        try:
            # Initialize Webex Teams API
            webex = WebexTeamsAPI(access_token=self.config["webex_token"])

            # Format the message
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            message = f"""
🏥 **Catalyst Center Daily Health Report** - {timestamp}

{summary}

📊 **Detailed Report:** See attached PDF for complete analysis.
"""

            # Send message with PDF attachment
            self.logger.info("Sending health report to Webex space...")

            # Send the message with file attachment
            webex.messages.create(
                roomId=self.config["webex_space_id"],
                markdown=message,
                files=[pdf_filepath]
            )

            self.logger.info("Health report sent to Webex successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to send Webex message: {e}")
            return False

class HealthReportGenerator:
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

            # Add debugging for fabric health processing
            if fabric_health:
                logging.info(f"Processing {len(fabric_health)} fabric health records")
                logging.info(f"Sample fabric health data: {fabric_health[0] if fabric_health else 'None'}")

            if all_sites:
                logging.info(f"Processing {len(all_sites)} sites for mapping")
                logging.info(f"Sample site data: {all_sites[0] if all_sites else 'None'}")

            if fabric_sites:
                logging.info(f"Processing {len(fabric_sites)} fabric sites")
                logging.info(f"Sample fabric site data: {fabric_sites[0] if fabric_sites else 'None'}")

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

        # Build PDF
        doc.build(story)

        logging.info(f"Combined health PDF report generated: {filepath}")
        return filepath

def main():
    """Main function to run the health monitoring"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Cisco Catalyst Center Health Monitor with AI Analysis')
    parser.add_argument('--ai-summary', action='store_true',
                       help='Enable AI-powered analysis and Webex messaging of health report')
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

        # Validate configuration
        if not all([
            CATALYST_CENTER_CONFIG["base_url"] != "https://your-catalyst-center.example.com",
            CATALYST_CENTER_CONFIG["username"] != "your_username",
            CATALYST_CENTER_CONFIG["password"] != "your_password"
        ]):
            logging.error("Please update the CATALYST_CENTER_CONFIG with your environment details")
            logging.error("You can also set environment variables:")
            logging.error("  CATALYST_CENTER_URL")
            logging.error("  CATALYST_CENTER_USERNAME")
            logging.error("  CATALYST_CENTER_PASSWORD")
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
                if isinstance(health_score, (int, float)) and health_score <= 7:
                    devices.append(device)

            poor_count = len([d for d in devices if d.get('overallHealth', 0) <= 3])
            fair_count = len([d for d in devices if 3 < d.get('overallHealth', 0) <= 7])

            logging.info(f"Retrieved {len(all_devices)} total devices, filtered to {len(devices)} poor/fair health devices")
            logging.info(f"Breakdown: {poor_count} poor health, {fair_count} fair health devices")
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
        logging.info("Collecting critical (P1) and high priority (P2) intent issues...")
        try:
            p1_issues = client.get_intent_issues(priority="P1", issue_status="active")
            p2_issues = client.get_intent_issues(priority="P2", issue_status="active")
            intent_issues = p1_issues + p2_issues
            logging.info(f"Retrieved {len(p1_issues)} P1 and {len(p2_issues)} P2 intent issues")
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
            logging.info(f"Retrieved fabric health data for {len(fabric_health)} sites")

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
            poor_applications = client.get_application_health(application_health="POOR")
            fair_applications = client.get_application_health(application_health="FAIR")
            applications = poor_applications + fair_applications
            logging.info(f"Retrieved {len(applications)} applications with Poor or Fair health")
        except Exception as e:
            logging.warning(f"Failed to collect application health data: {e}")
            applications = []

        # Collect client health (Poor and Fair clients for both wired and wireless)
        logging.info("Collecting client health...")
        try:
            # Use Data API to get individual client records with detailed information
            logging.info("Using Data API for detailed client information...")
            all_clients = client.get_clients()
            # Filter for poor and fair health clients
            def categorize_client_health(health_score):
                if not isinstance(health_score, (int, float)):
                    return 'UNKNOWN'
                if health_score < 4:
                    return 'POOR'
                elif health_score < 7:
                    return 'FAIR'
                else:
                    return 'GOOD'

            clients = [c for c in all_clients if categorize_client_health(c.get('health', {}).get('overallScore', 0)) in ['POOR', 'FAIR']]
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
            'timestamp': datetime.now().isoformat()
        }

        # Generate reports
        report_generator = HealthReportGenerator()

        # Generate only the combined report (includes all health data)
        combined_report = report_generator.generate_combined_pdf(
            devices, all_devices, all_issues, fabric_sites, fabric_health, all_sites,
            applications, clients, ise_health, maglev_services, system_backup,
            backup_history, system_updates, timestamp
        )

        logging.info("Health monitoring completed successfully!")
        logging.info(f"Report generated:")
        logging.info(f"  - Comprehensive Health Report: {combined_report}")

        # Handle AI analysis and Webex messaging if requested
        webex_success = False
        if args.ai_summary:
            logging.info("AI analysis requested, generating summary...")

            # Initialize AI analyzer
            ai_analyzer = AIHealthAnalyzer(AI_CONFIG)

            # Generate AI summary
            ai_summary = ai_analyzer.analyze_health_data(health_data)

            # Print AI summary to console
            print("\n" + "="*70)
            print("🤖 AI HEALTH ANALYSIS SUMMARY")
            print("="*70)
            print(ai_summary)
            print("="*70)

            # Send to Webex if configured
            webex_notifier = WebexNotifier(AI_CONFIG)
            webex_success = webex_notifier.send_health_report(ai_summary, combined_report)

            if webex_success:
                logging.info("Health report sent to Webex successfully")
                print("\n📧 Health report sent to Webex space successfully!")
            else:
                logging.warning("Failed to send health report to Webex")
                print("\n⚠️  Failed to send health report to Webex. Check logs for details.")

        # Print summary
        print("\n" + "="*60)
        print("CATALYST CENTER HEALTH MONITORING SUMMARY")
        print("="*60)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Devices: {len(devices)}")
        print(f"Total Issues: {len(all_issues)} (Assurance: {len(assurance_issues)}, Intent P1/P2: {len(intent_issues)})")
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
                def categorize_health(score):
                    if not isinstance(score, (int, float)):
                        return 'UNKNOWN'
                    if score < 4:
                        return 'POOR'
                    elif score < 7:
                        return 'FAIR'
                    else:
                        return 'GOOD'

                poor_client_count = len([c for c in clients if categorize_health(c.get('health', {}).get('overallScore', 0)) == 'POOR'])
                fair_client_count = len([c for c in clients if categorize_health(c.get('health', {}).get('overallScore', 0)) == 'FAIR'])
                good_client_count = len([c for c in clients if categorize_health(c.get('health', {}).get('overallScore', 0)) == 'GOOD'])

                # Separate wired and wireless
                wired_poor = len([c for c in clients if categorize_health(c.get('health', {}).get('overallScore', 0)) == 'POOR' and c.get('type', '').upper() == 'WIRED'])
                wired_fair = len([c for c in clients if categorize_health(c.get('health', {}).get('overallScore', 0)) == 'FAIR' and c.get('type', '').upper() == 'WIRED'])
                wireless_poor = len([c for c in clients if categorize_health(c.get('health', {}).get('overallScore', 0)) == 'POOR' and c.get('type', '').upper() == 'WIRELESS'])
                wireless_fair = len([c for c in clients if categorize_health(c.get('health', {}).get('overallScore', 0)) == 'FAIR' and c.get('type', '').upper() == 'WIRELESS'])

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

        if args.ai_summary:
            print(f"  🤖 AI Analysis: {'✅ Completed' if 'ai_summary' in locals() else '❌ Failed'}")
            print(f"  📧 Webex Notification: {'✅ Sent' if webex_success else '❌ Failed'}")

        print("="*60)

    except KeyboardInterrupt:
        logging.info("Script interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
