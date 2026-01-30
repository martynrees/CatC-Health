"""
Abstract Notification Channel Module

Base class for all notification delivery channels (Email, Webex, Teams, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import logging


class NotificationChannel(ABC):
    """
    Abstract base class for notification delivery channels.
    
    All notification channels (Email, Webex, Teams, etc.) should extend this class
    and implement the required methods.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the notification channel.
        
        Args:
            config: Configuration dictionary specific to this channel
        """
        self.config = config
        self.logger = self._setup_logging()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for this notification channel"""
        logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        logger.setLevel(logging.INFO)
        return logger
    
    @abstractmethod
    def send(self, message: str, pdf_filepath: Optional[str] = None) -> bool:
        """
        Send a notification through this channel.
        
        Args:
            message: The notification message content (text or HTML)
            pdf_filepath: Optional path to PDF report to attach/link
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def is_configured(self) -> bool:
        """
        Check if this channel is properly configured.
        
        Returns:
            True if all required configuration is present, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_config(self) -> tuple[bool, Optional[str]]:
        """
        Validate the configuration for this channel.
        
        Returns:
            Tuple of (is_valid, error_message)
            - is_valid: True if configuration is valid
            - error_message: None if valid, error description if invalid
        """
        pass
    
    def get_channel_name(self) -> str:
        """
        Get the human-readable name of this channel.
        
        Returns:
            Channel name (e.g., "Email", "Webex", "Teams")
        """
        return self.__class__.__name__.replace("Notifier", "")
