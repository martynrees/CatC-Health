"""
Webex Teams Notification Module

Sends health reports and summaries to Cisco Webex Teams spaces.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from .notification_channel import NotificationChannel

try:
    from webexteamssdk import WebexTeamsAPI
    WEBEX_AVAILABLE = True
except ImportError:
    WEBEX_AVAILABLE = False


class WebexNotifier(NotificationChannel):
    """Webex Teams notification channel implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Webex Teams notifier.
        
        Args:
            config: Configuration dictionary with webex_token and webex_space_id
        """
        super().__init__(config)
    
    def is_configured(self) -> bool:
        """
        Check if Webex is properly configured.
        
        Returns:
            True if token and space ID are present
        """
        return bool(
            self.config.get("webex_token") and 
            self.config.get("webex_space_id") and
            WEBEX_AVAILABLE
        )
    
    def validate_config(self) -> tuple[bool, Optional[str]]:
        """
        Validate Webex configuration.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not WEBEX_AVAILABLE:
            return False, "webexteamssdk is not installed. Install with: pip install webexteamssdk"
        
        if not self.config.get("webex_token"):
            return False, "WEBEX_BOT_TOKEN is not configured"
        
        if not self.config.get("webex_space_id"):
            return False, "WEBEX_SPACE_ID is not configured"
        
        return True, None
    
    def send(self, message: str, pdf_filepath: Optional[str] = None) -> bool:
        """
        Send notification to Webex Teams space.
        
        Args:
            message: Message content (supports markdown)
            pdf_filepath: Optional PDF file to attach
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.is_configured():
            is_valid, error = self.validate_config()
            self.logger.error(f"Webex not properly configured: {error}")
            return False
        
        try:
            webex = WebexTeamsAPI(access_token=self.config["webex_token"])
            
            # Format message with markdown
            formatted_message = self._format_message(message)
            
            # Send message with optional attachment
            if pdf_filepath:
                webex.messages.create(
                    roomId=self.config["webex_space_id"],
                    markdown=formatted_message,
                    files=[pdf_filepath]
                )
                self.logger.info(f"Webex notification sent successfully with PDF attachment")
            else:
                webex.messages.create(
                    roomId=self.config["webex_space_id"],
                    markdown=formatted_message
                )
                self.logger.info("Webex notification sent successfully")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send Webex notification: {e}")
            return False
    
    def _format_message(self, message: str) -> str:
        """
        Format message for Webex with markdown styling.
        
        Args:
            message: Raw message text
            
        Returns:
            Formatted markdown message
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        formatted = f"""
**🏥 Cisco Catalyst Center Health Report**

**Generated:** {timestamp}

---

{message}

---
*Automated health monitoring report*
"""
        return formatted.strip()
    
    # Backward compatibility method
    def send_health_report(self, summary: str, pdf_filepath: str) -> bool:
        """
        Legacy method for backward compatibility.
        
        Args:
            summary: Health summary text
            pdf_filepath: Path to PDF report
            
        Returns:
            True if sent successfully
        """
        return self.send(summary, pdf_filepath)
