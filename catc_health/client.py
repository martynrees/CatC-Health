"""
Catalyst Center API Client

This module provides a client for interacting with Cisco Catalyst Center APIs
with automatic retry logic for transient failures.
"""

import base64
import logging
from typing import Dict, List, Optional, Any

import requests
import urllib3
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log
)

from .config import API_ENDPOINTS

# Suppress InsecureRequestWarning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CatalystCenterClient:
    """Client for interacting with Cisco Catalyst Center APIs with retry logic"""

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

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.WARNING)
    )
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make HTTP request with retry logic

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL for the request
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        return self.session.request(method, url, **kwargs)

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
            response = self._make_request(
                "GET",
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
            response = self._make_request(
                "GET",
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
            response = self._make_request(
                "GET",
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
            response = self._make_request(
                "GET",
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
        """Get SDA fabric sites"""
        url = f"{self.base_url}{API_ENDPOINTS['fabric_sites']}"
        params = {"limit": str(limit)}

        try:
            self.logger.info(f"Fetching fabric sites data with limit: {limit}")
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            sites = data.get("response", [])
            self.logger.info(f"Retrieved {len(sites)} fabric sites")
            return sites
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get fabric sites: {e}")
            return []

    def get_sites(self, limit: int = 500) -> List[Dict]:
        """Get all sites information"""
        url = f"{self.base_url}{API_ENDPOINTS['sites']}"
        params = {"limit": str(limit)}

        try:
            self.logger.info(f"Fetching sites data with limit: {limit}")
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            sites = data.get("response", [])
            self.logger.info(f"Retrieved {len(sites)} sites")
            return sites
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get sites: {e}")
            return []

    def get_site_by_id(self, site_id: str) -> Dict:
        """Get specific site information by ID"""
        url = f"{self.base_url}{API_ENDPOINTS['sites']}/{site_id}"

        try:
            self.logger.info(f"Fetching site data for ID: {site_id}")
            response = self._make_request("GET", url, verify=self.verify_ssl, timeout=self.timeout)
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
        """Get SDA fabric site health summaries"""
        url = f"{self.base_url}{API_ENDPOINTS['fabric_site_health']}"
        params = {"limit": str(limit)}
        if start_time:
            params["startTime"] = str(start_time)
        if end_time:
            params["endTime"] = str(end_time)

        try:
            self.logger.info(f"Fetching fabric site health data with params: {params}")
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
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
        """Get application health using Intent API"""
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
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            applications = data.get("response", [])
            self.logger.info(f"Retrieved {len(applications)} applications")
            return applications
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get application health: {e}")
            return []

    def get_network_applications(self, site_id: str, start_time: Optional[int] = None,
                                end_time: Optional[int] = None, limit: int = 500) -> List[Dict]:
        """Get network applications with detailed health metrics using Data API"""
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
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            applications = data.get("response", [])
            self.logger.info(f"Retrieved {len(applications)} network applications")
            return applications
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get network applications: {e}")
            return []

    def get_client_health(self, site_id: Optional[str] = None, connection_type: Optional[str] = None,
                         health_score: Optional[str] = None, limit: int = 500) -> List[Dict]:
        """Get client health using Intent API"""
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
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            clients = data.get("response", [])
            self.logger.info(f"Retrieved {len(clients)} clients")
            return clients
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get client health: {e}")
            return []

    def get_clients(self, site_hierarchy: Optional[str] = None,
                   connection_type: Optional[str] = None, limit: int = 500) -> List[Dict]:
        """Get clients with detailed information using Data API"""
        url = f"{self.base_url}{API_ENDPOINTS['clients']}"
        params = {"limit": str(limit)}
        if site_hierarchy:
            params["siteHierarchy"] = site_hierarchy
        if connection_type:
            params["connectionType"] = connection_type

        try:
            self.logger.info(f"Fetching clients data with params: {params}")
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            clients = data.get("response", [])
            self.logger.info(f"Retrieved {len(clients)} clients with detailed information")
            return clients
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get clients: {e}")
            return []

    def get_ise_health(self, limit: int = 500) -> List[Dict]:
        """Get Cisco ISE health status"""
        url = f"{self.base_url}{API_ENDPOINTS['ise_health']}"
        params = {"limit": str(limit)}

        try:
            self.logger.info("Fetching Cisco ISE health status")
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            ise_nodes = data.get("response", [])
            self.logger.info(f"Retrieved ISE health data for {len(ise_nodes)} nodes")
            return ise_nodes
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get ISE health: {e}")
            return []

    def get_maglev_services(self, limit: int = 500) -> List[Dict]:
        """Get Maglev services summary"""
        url = f"{self.base_url}{API_ENDPOINTS['maglev_services']}"
        params = {"limit": str(limit)}

        try:
            self.logger.info("Fetching Maglev services summary")
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            services = data.get("response", [])
            self.logger.info(f"Retrieved {len(services)} Maglev services")
            return services
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Maglev services: {e}")
            return []

    def get_system_backup(self, limit: int = 500) -> List[Dict]:
        """Get system backup information"""
        url = f"{self.base_url}{API_ENDPOINTS['system_backup']}"
        params = {"limit": str(limit)}

        try:
            self.logger.info("Fetching system backup information")
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            backups = data.get("response", [])
            self.logger.info(f"Retrieved {len(backups)} system backups")
            return backups
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get system backup: {e}")
            return []

    def get_backup_history(self, limit: int = 500) -> List[Dict]:
        """Get backup history"""
        url = f"{self.base_url}{API_ENDPOINTS['backup_history']}"
        params = {"limit": str(limit)}

        try:
            self.logger.info("Fetching backup history")
            response = self._make_request("GET", url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            history = data.get("response", [])
            self.logger.info(f"Retrieved backup history with {len(history)} records")
            return history
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get backup history: {e}")
            return []

    def get_system_updates(self) -> Dict:
        """Get system update information"""
        url = f"{self.base_url}{API_ENDPOINTS['system_updates']}"

        try:
            self.logger.info("Fetching system update information")
            response = self._make_request("GET", url, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            update_info = data.get("response", {})
            self.logger.info("Retrieved system update information")
            return update_info
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get system updates: {e}")
            return {}
