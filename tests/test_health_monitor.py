"""
Unit tests for Catalyst Center Health Monitor
"""

import pytest
from catc_health.utils import categorize_health
from catc_health.api_adapter import APIFieldAdapter


class TestUtils:
    """Test utility functions"""
    
    def test_categorize_health_poor(self):
        """Test POOR health categorization"""
        assert categorize_health(0) == 'POOR'
        assert categorize_health(1) == 'POOR'
        assert categorize_health(3) == 'POOR'
    
    def test_categorize_health_fair(self):
        """Test FAIR health categorization"""
        assert categorize_health(4) == 'FAIR'
        assert categorize_health(5) == 'FAIR'
        assert categorize_health(6) == 'FAIR'
    
    def test_categorize_health_good(self):
        """Test GOOD health categorization"""
        assert categorize_health(7) == 'GOOD'
        assert categorize_health(8) == 'GOOD'
        assert categorize_health(10) == 'GOOD'
    
    def test_categorize_health_invalid(self):
        """Test invalid health score"""
        assert categorize_health("invalid") == 'UNKNOWN'
        assert categorize_health(None) == 'UNKNOWN'


class TestAPIFieldAdapter:
    """Test API field adapter"""
    
    def test_normalize_device_data(self):
        """Test device data normalization"""
        raw_device = {
            'overallHealth': 5,
            'name': 'Switch-01',
            'ipAddress': '10.0.0.1',
            'macAddress': 'AA:BB:CC:DD:EE:FF',
            'role': 'ACCESS',
            'location': 'Building A'
        }
        
        normalized = APIFieldAdapter.normalize_device_data(raw_device)
        
        assert normalized['health_score'] == 5
        assert normalized['name'] == 'Switch-01'
        assert normalized['ip_address'] == '10.0.0.1'
        assert normalized['mac_address'] == 'AA:BB:CC:DD:EE:FF'
        assert normalized['role'] == 'ACCESS'
    
    def test_normalize_client_data(self):
        """Test client data normalization"""
        raw_client = {
            'health': {'overallScore': 8},
            'connectionType': 'WIRED',
            'ipAddress': '192.168.1.100',
            'macAddress': '11:22:33:44:55:66'
        }
        
        normalized = APIFieldAdapter.normalize_client_data(raw_client)
        
        assert normalized['health_score'] == 8
        assert normalized['connection_type'] == 'WIRED'
        assert normalized['ip_address'] == '192.168.1.100'
    
    def test_get_field_value_nested(self):
        """Test nested field retrieval"""
        data = {
            'health': {
                'overallScore': 7
            }
        }
        
        result = APIFieldAdapter.get_field_value(data, 'health_score', default=0)
        assert result == 7
    
    def test_normalize_batch(self):
        """Test batch normalization"""
        devices = [
            {'overallHealth': 5, 'name': 'Device1', 'ipAddress': '10.0.0.1'},
            {'overallHealth': 8, 'name': 'Device2', 'ipAddress': '10.0.0.2'}
        ]
        
        normalized = APIFieldAdapter.normalize_batch(devices, 'device')
        
        assert len(normalized) == 2
        assert normalized[0]['health_score'] == 5
        assert normalized[1]['health_score'] == 8


class TestConfiguration:
    """Test configuration module"""
    
    def test_validate_config_missing_env(self, monkeypatch):
        """Test validation with missing .env file"""
        # This would require mocking - placeholder for now
        pass
    
    def test_load_configuration(self):
        """Test configuration loading"""
        from catc_health.config import load_configuration
        
        config = load_configuration()
        
        assert 'catalyst_center' in config
        assert 'ai' in config
        assert 'api_endpoints' in config
        assert 'health_filters' in config


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
