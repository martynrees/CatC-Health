"""
API Field Adapter for Catalyst Center

Handles field name mapping and normalization across different API versions.
"""

from typing import Dict, Any, List


class APIFieldAdapter:
    """Adapter for normalizing API response fields across different versions"""
    
    # Field mappings for different API endpoints
    CLIENT_FIELD_MAPPING = {
        # Common alternate field names for client data
        'health_score': ['healthScore', 'overallScore', 'health.overallScore'],
        'connection_type': ['connectionType', 'type', 'clientType'],
        'ip_address': ['ipAddress', 'ip', 'hostIpAddress'],
        'mac_address': ['macAddress', 'mac', 'hostMac'],
        'ssid': ['ssid', 'SSID', 'wlanName'],
        'ap_name': ['apName', 'accessPointName', 'apMacAddress']
    }
    
    DEVICE_FIELD_MAPPING = {
        'health_score': ['overallHealth', 'healthScore', 'health'],
        'name': ['name', 'hostname', 'deviceName'],
        'ip_address': ['ipAddress', 'managementIpAddress', 'ip'],
        'mac_address': ['macAddress', 'mac'],
        'role': ['role', 'deviceRole', 'family'],
        'site': ['site', 'location', 'siteHierarchy']
    }
    
    ISSUE_FIELD_MAPPING = {
        'priority': ['priority', 'severity', 'issuePriority'],
        'name': ['name', 'title', 'issueName'],
        'description': ['description', 'details', 'issueDescription'],
        'affected_devices': ['affectedDevices', 'deviceCount', 'impactedDevices']
    }
    
    @classmethod
    def get_field_value(cls, data: Dict[str, Any], field_type: str, 
                       default: Any = None) -> Any:
        """
        Get field value from data using field mappings
        
        Args:
            data: Dictionary containing the data
            field_type: Type of field to retrieve (e.g., 'health_score')
            default: Default value if field not found
            
        Returns:
            Field value or default
        """
        # Determine which mapping to use
        if field_type in cls.CLIENT_FIELD_MAPPING:
            possible_fields = cls.CLIENT_FIELD_MAPPING[field_type]
        elif field_type in cls.DEVICE_FIELD_MAPPING:
            possible_fields = cls.DEVICE_FIELD_MAPPING[field_type]
        elif field_type in cls.ISSUE_FIELD_MAPPING:
            possible_fields = cls.ISSUE_FIELD_MAPPING[field_type]
        else:
            return default
        
        # Try each possible field name
        for field_name in possible_fields:
            # Handle nested fields (e.g., 'health.overallScore')
            if '.' in field_name:
                value = cls._get_nested_field(data, field_name)
                if value is not None:
                    return value
            else:
                if field_name in data:
                    return data[field_name]
        
        return default
    
    @classmethod
    def _get_nested_field(cls, data: Dict[str, Any], field_path: str) -> Any:
        """
        Get nested field value using dot notation
        
        Args:
            data: Dictionary containing the data
            field_path: Dot-separated field path (e.g., 'health.overallScore')
            
        Returns:
            Field value or None if not found
        """
        keys = field_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    @classmethod
    def normalize_client_data(cls, client: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize client data to consistent field names
        
        Args:
            client: Raw client data dictionary
            
        Returns:
            Normalized client data dictionary
        """
        return {
            'health_score': cls.get_field_value(client, 'health_score', 0),
            'connection_type': cls.get_field_value(client, 'connection_type', 'UNKNOWN'),
            'ip_address': cls.get_field_value(client, 'ip_address', 'N/A'),
            'mac_address': cls.get_field_value(client, 'mac_address', 'N/A'),
            'ssid': cls.get_field_value(client, 'ssid', 'N/A'),
            'ap_name': cls.get_field_value(client, 'ap_name', 'N/A'),
            '_raw_data': client  # Keep raw data for reference
        }
    
    @classmethod
    def normalize_device_data(cls, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize device data to consistent field names
        
        Args:
            device: Raw device data dictionary
            
        Returns:
            Normalized device data dictionary
        """
        return {
            'health_score': cls.get_field_value(device, 'health_score', 0),
            'name': cls.get_field_value(device, 'name', 'Unknown'),
            'ip_address': cls.get_field_value(device, 'ip_address', 'N/A'),
            'mac_address': cls.get_field_value(device, 'mac_address', 'N/A'),
            'role': cls.get_field_value(device, 'role', 'Unknown'),
            'site': cls.get_field_value(device, 'site', 'Unknown'),
            '_raw_data': device  # Keep raw data for reference
        }
    
    @classmethod
    def normalize_issue_data(cls, issue: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize issue data to consistent field names
        
        Args:
            issue: Raw issue data dictionary
            
        Returns:
            Normalized issue data dictionary
        """
        return {
            'priority': cls.get_field_value(issue, 'priority', 'Unknown'),
            'name': cls.get_field_value(issue, 'name', 'Unknown Issue'),
            'description': cls.get_field_value(issue, 'description', 'No description'),
            'affected_devices': cls.get_field_value(issue, 'affected_devices', []),
            '_raw_data': issue  # Keep raw data for reference
        }
    
    @classmethod
    def normalize_batch(cls, data_list: List[Dict[str, Any]], 
                       data_type: str) -> List[Dict[str, Any]]:
        """
        Normalize a batch of data items
        
        Args:
            data_list: List of data dictionaries
            data_type: Type of data ('client', 'device', or 'issue')
            
        Returns:
            List of normalized data dictionaries
        """
        normalizers = {
            'client': cls.normalize_client_data,
            'device': cls.normalize_device_data,
            'issue': cls.normalize_issue_data
        }
        
        normalizer = normalizers.get(data_type)
        if not normalizer:
            raise ValueError(f"Unknown data type: {data_type}")
        
        return [normalizer(item) for item in data_list]
