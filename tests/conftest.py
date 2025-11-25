"""
Test fixtures for Catalyst Center Health Monitor tests
"""

import pytest


@pytest.fixture
def sample_device_data():
    """Sample device health data"""
    return {
        'overallHealth': 5,
        'name': 'Test-Switch-01',
        'ipAddress': '10.1.1.1',
        'macAddress': 'AA:BB:CC:DD:EE:FF',
        'role': 'ACCESS',
        'site': 'Building A/Floor 1'
    }


@pytest.fixture
def sample_client_data():
    """Sample client health data"""
    return {
        'health': {'overallScore': 7},
        'connectionType': 'WIRELESS',
        'ipAddress': '192.168.1.100',
        'macAddress': '11:22:33:44:55:66',
        'ssid': 'Corp-WiFi',
        'apName': 'AP-01'
    }


@pytest.fixture
def sample_issue_data():
    """Sample issue data"""
    return {
        'priority': 'P1',
        'name': 'Link Down on Switch-01',
        'description': 'Critical link failure detected',
        'affectedDevices': ['Switch-01', 'Switch-02']
    }


@pytest.fixture
def sample_health_data():
    """Complete sample health data for AI analysis"""
    return {
        'all_devices': [
            {'overallHealth': 2, 'name': 'Switch-01', 'ipAddress': '10.0.0.1'},
            {'overallHealth': 5, 'name': 'Switch-02', 'ipAddress': '10.0.0.2'},
            {'overallHealth': 9, 'name': 'Router-01', 'ipAddress': '10.0.0.3'}
        ],
        'issues': [
            {'priority': 'P1', 'name': 'Critical Link Failure'},
            {'priority': 'P2', 'name': 'High CPU Usage'}
        ],
        'fabric_health': [
            {'name': 'Site-A', 'goodHealthPercentage': 45},
            {'name': 'Site-B', 'goodHealthPercentage': 85}
        ],
        'clients': [],
        'ise_health': [{'status': 'AVAILABLE'}],
        'maglev_services': [{'status': 'running'}, {'status': 'stopped'}],
        'system_backup': [{'status': 'SUCCESS'}]
    }
