"""
Notification Manager Module

Orchestrates multiple notification channels (Email, Webex, Teams).
"""

import logging
from typing import List, Dict, Any, Optional

from .notification_channel import NotificationChannel
from .email_notifier import EmailNotifier
from .webex_notifier import WebexNotifier
from .teams_notifier import TeamsNotifier


class NotificationManager:
    """
    Manager class to orchestrate multiple notification channels.
    
    Handles sending notifications to multiple channels simultaneously with
    independent error handling per channel.
    """
    
    def __init__(self, email_config: Dict[str, Any], webex_config: Dict[str, Any], 
                 teams_config: Dict[str, Any]):
        """
        Initialize the notification manager.
        
        Args:
            email_config: Email notification configuration
            webex_config: Webex notification configuration
            teams_config: Teams notification configuration
        """
        self.email_config = email_config
        self.webex_config = webex_config
        self.teams_config = teams_config
        self.logger = self._setup_logging()
        
        # Initialize channels
        self.channels = self._initialize_channels()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for notification manager"""
        logger = logging.getLogger(f"{__name__}.NotificationManager")
        logger.setLevel(logging.INFO)
        return logger
    
    def _initialize_channels(self) -> Dict[str, NotificationChannel]:
        """
        Initialize all notification channels.
        
        Returns:
            Dictionary of channel name -> channel instance
        """
        channels = {}
        
        # Initialize Email channel
        try:
            email_notifier = EmailNotifier(self.email_config)
            channels['email'] = email_notifier
            self.logger.debug("Email channel initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize email channel: {e}")
        
        # Initialize Webex channel
        try:
            webex_notifier = WebexNotifier(self.webex_config)
            channels['webex'] = webex_notifier
            self.logger.debug("Webex channel initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize Webex channel: {e}")
        
        # Initialize Teams channel
        try:
            teams_notifier = TeamsNotifier(self.teams_config)
            channels['teams'] = teams_notifier
            self.logger.debug("Teams channel initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize Teams channel: {e}")
        
        return channels
    
    def get_enabled_channels(self, cli_overrides: Optional[Dict[str, bool]] = None) -> List[str]:
        """
        Get list of enabled channels based on config and CLI overrides.
        
        Args:
            cli_overrides: Optional dict of channel overrides from CLI
                          e.g., {'email': True, 'webex': False}
        
        Returns:
            List of enabled channel names
        """
        enabled = []
        
        # Check each channel
        for channel_name in ['email', 'webex', 'teams']:
            # CLI override takes precedence
            if cli_overrides and channel_name in cli_overrides:
                if cli_overrides[channel_name]:
                    enabled.append(channel_name)
                continue
            
            # Otherwise use config
            if channel_name == 'email' and self.email_config.get('enabled'):
                enabled.append(channel_name)
            elif channel_name == 'webex' and self.webex_config.get('enabled'):
                enabled.append(channel_name)
            elif channel_name == 'teams' and self.teams_config.get('enabled'):
                enabled.append(channel_name)
        
        return enabled
    
    def validate_channels(self, channel_names: Optional[List[str]] = None) -> Dict[str, tuple[bool, Optional[str]]]:
        """
        Validate configuration for specified channels.
        
        Args:
            channel_names: List of channel names to validate, or None for all
            
        Returns:
            Dictionary of channel_name -> (is_valid, error_message)
        """
        if channel_names is None:
            channel_names = list(self.channels.keys())
        
        results = {}
        for channel_name in channel_names:
            if channel_name in self.channels:
                channel = self.channels[channel_name]
                results[channel_name] = channel.validate_config()
            else:
                results[channel_name] = (False, f"Channel '{channel_name}' not initialized")
        
        return results
    
    def send_notifications(self, message: str, pdf_filepath: Optional[str] = None,
                          enabled_channels: Optional[List[str]] = None,
                          cli_overrides: Optional[Dict[str, bool]] = None) -> Dict[str, bool]:
        """
        Send notifications to all enabled channels.
        
        Args:
            message: Notification message content
            pdf_filepath: Optional PDF file path to attach
            enabled_channels: Optional list of channel names to use
            cli_overrides: Optional CLI flag overrides
            
        Returns:
            Dictionary of channel_name -> success (bool)
        """
        # Determine which channels to use
        if enabled_channels is None:
            enabled_channels = self.get_enabled_channels(cli_overrides)
        
        if not enabled_channels:
            self.logger.warning("No notification channels enabled")
            return {}
        
        self.logger.info(f"Sending notifications to {len(enabled_channels)} channel(s): {', '.join(enabled_channels)}")
        
        results = {}
        
        # Send to each enabled channel
        for channel_name in enabled_channels:
            if channel_name not in self.channels:
                self.logger.error(f"Channel '{channel_name}' not available")
                results[channel_name] = False
                continue
            
            channel = self.channels[channel_name]
            
            # Validate before sending
            is_valid, error = channel.validate_config()
            if not is_valid:
                self.logger.error(f"Cannot send to {channel_name}: {error}")
                results[channel_name] = False
                continue
            
            # Send notification
            try:
                success = channel.send(message, pdf_filepath)
                results[channel_name] = success
                
                if success:
                    self.logger.info(f"✅ {channel_name.capitalize()} notification sent successfully")
                else:
                    self.logger.warning(f"❌ {channel_name.capitalize()} notification failed")
                    
            except Exception as e:
                self.logger.error(f"Exception sending to {channel_name}: {e}")
                results[channel_name] = False
        
        # Log summary
        successful = sum(1 for success in results.values() if success)
        total = len(results)
        self.logger.info(f"Notification summary: {successful}/{total} channels succeeded")
        
        return results
    
    def get_channel_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of all channels.
        
        Returns:
            Dictionary with channel status information
        """
        status = {}
        
        for channel_name, channel in self.channels.items():
            is_configured = channel.is_configured()
            is_valid, error = channel.validate_config()
            
            # Check if enabled in config
            if channel_name == 'email':
                enabled = self.email_config.get('enabled', False)
            elif channel_name == 'webex':
                enabled = self.webex_config.get('enabled', False)
            elif channel_name == 'teams':
                enabled = self.teams_config.get('enabled', False)
            else:
                enabled = False
            
            status[channel_name] = {
                'enabled': enabled,
                'configured': is_configured,
                'valid': is_valid,
                'error': error,
                'channel_type': channel.get_channel_name()
            }
        
        return status
    
    def print_channel_status(self) -> None:
        """Print channel status to console"""
        status = self.get_channel_status()
        
        print("\n" + "="*60)
        print("Notification Channel Status")
        print("="*60)
        
        for channel_name, info in status.items():
            status_icon = "✅" if (info['enabled'] and info['valid']) else "❌"
            print(f"\n{status_icon} {channel_name.upper()}")
            print(f"   Enabled: {info['enabled']}")
            print(f"   Configured: {info['configured']}")
            print(f"   Valid: {info['valid']}")
            if info['error']:
                print(f"   Error: {info['error']}")
        
        print("="*60 + "\n")
