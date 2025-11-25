"""
Utility functions for Catalyst Center Health Monitor

Common helper functions used across the application.
"""

from typing import Any


def categorize_health(health_score: Any) -> str:
    """
    Categorize health based on numeric health score
    
    Args:
        health_score: Numeric health score (typically 0-10)
        
    Returns:
        Health category: 'POOR', 'FAIR', or 'GOOD'
    """
    if not isinstance(health_score, (int, float)):
        return 'UNKNOWN'
    
    if health_score <= 3:
        return 'POOR'
    elif health_score < 7:
        return 'FAIR'
    else:
        return 'GOOD'
