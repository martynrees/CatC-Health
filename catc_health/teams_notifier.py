"""
MS Teams Notification Module

Sends health reports and summaries to Microsoft Teams channels via incoming webhooks.
"""

import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import requests

from .notification_channel import NotificationChannel


class TeamsNotifier(NotificationChannel):
    """Microsoft Teams notification channel implementation using incoming webhooks"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Teams notifier.
        
        Args:
            config: Configuration dictionary with Teams webhook URL
        """
        super().__init__(config)
    
    def is_configured(self) -> bool:
        """
        Check if Teams is properly configured.
        
        Returns:
            True if webhook URL is present
        """
        webhook_url = self.config.get("teams_webhook_url")
        return bool(webhook_url and webhook_url.startswith("https://"))
    
    def validate_config(self) -> tuple[bool, Optional[str]]:
        """
        Validate Teams configuration.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        webhook_url = self.config.get("teams_webhook_url")
        
        if not webhook_url:
            return False, "TEAMS_WEBHOOK_URL is not configured"
        
        if not webhook_url.startswith("https://"):
            return False, "TEAMS_WEBHOOK_URL must be a valid HTTPS URL"
        
        if "webhook" not in webhook_url.lower():
            return False, "TEAMS_WEBHOOK_URL does not appear to be a valid webhook URL"
        
        return True, None
    
    def send(self, message: str, pdf_filepath: Optional[str] = None) -> bool:
        """
        Send notification to Teams channel via webhook.
        
        Args:
            message: Message content (plain text)
            pdf_filepath: Optional PDF file path (note: webhooks cannot upload files,
                         will include note about PDF being saved locally)
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.is_configured():
            is_valid, error = self.validate_config()
            self.logger.error(f"Teams not properly configured: {error}")
            return False
        
        try:
            # Create message card
            card = self._create_message_card(message, pdf_filepath)
            
            # Send to webhook
            response = requests.post(
                self.config["teams_webhook_url"],
                json=card,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            response.raise_for_status()
            
            if pdf_filepath:
                self.logger.info("Teams notification sent successfully (PDF saved locally)")
            else:
                self.logger.info("Teams notification sent successfully")
            
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to send Teams notification: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending Teams notification: {e}")
            return False
    
    def _create_message_card(self, message: str, pdf_filepath: Optional[str] = None) -> Dict[str, Any]:
        """
        Create Teams MessageCard JSON payload.
        
        Args:
            message: Message content
            pdf_filepath: Optional PDF file path
            
        Returns:
            MessageCard dictionary
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format message for Teams (convert markdown-style formatting)
        formatted_message = self._format_message_for_teams(message)
        
        # Create sections
        sections = [
            {
                "activityTitle": "🏥 Cisco Catalyst Center Health Report",
                "activitySubtitle": f"Generated: {timestamp}",
                "activityImage": "https://upload.wikimedia.org/wikipedia/commons/thumb/0/08/Cisco_logo_blue_2016.svg/200px-Cisco_logo_blue_2016.svg.png",
                "facts": self._extract_facts_from_message(message),
                "text": formatted_message
            }
        ]
        
        # Add PDF note if applicable
        if pdf_filepath:
            import os
            filename = os.path.basename(pdf_filepath) if pdf_filepath else "health_report.pdf"
            sections.append({
                "activityTitle": "📊 Detailed Report",
                "text": f"**PDF Report Generated:** `{filename}`\n\n"
                       f"The detailed PDF report has been saved locally. "
                       f"Please check the reports directory on the monitoring server."
            })
        
        # Create the message card
        card = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "Catalyst Center Health Report",
            "themeColor": "0066CC",
            "sections": sections,
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "View Documentation",
                    "targets": [
                        {
                            "os": "default",
                            "uri": "https://www.cisco.com/c/en/us/support/cloud-systems-management/dna-center/series.html"
                        }
                    ]
                }
            ]
        }
        
        return card
    
    def _format_message_for_teams(self, message: str) -> str:
        """
        Format message content for Teams display.
        
        Args:
            message: Raw message text
            
        Returns:
            Formatted message for Teams
        """
        # Teams MessageCards support a limited subset of markdown
        # Convert bold indicators
        formatted = message.replace("**", "**")  # Keep as-is
        
        # Convert emoji shortcodes if needed
        formatted = formatted.replace(":warning:", "⚠️")
        formatted = formatted.replace(":fire:", "🔥")
        formatted = formatted.replace(":check:", "✅")
        
        # Limit length for Teams
        max_length = 3000
        if len(formatted) > max_length:
            formatted = formatted[:max_length] + "\n\n... [Message truncated for Teams display]"
        
        return formatted
    
    def _extract_facts_from_message(self, message: str) -> list[Dict[str, str]]:
        """
        Extract key facts from message for Teams card display.
        
        Args:
            message: Message content
            
        Returns:
            List of fact dictionaries with name/value pairs
        """
        facts = []
        
        # Try to extract some basic stats if present
        lines = message.split('\n')
        
        # Look for lines with colons (key: value patterns)
        for line in lines[:10]:  # Check first 10 lines
            if ':' in line and len(line) < 100:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    name = parts[0].strip().replace('**', '').replace('*', '')
                    value = parts[1].strip().replace('**', '').replace('*', '')
                    if name and value and len(name) < 50:
                        facts.append({"name": name, "value": value})
        
        # If no facts found, add a timestamp fact
        if not facts:
            facts.append({
                "name": "Report Type",
                "value": "Network Health Summary"
            })
        
        # Limit to 5 facts for readability
        return facts[:5]
    
    def _create_adaptive_card(self, message: str, pdf_filepath: Optional[str] = None) -> Dict[str, Any]:
        """
        Create Teams Adaptive Card JSON payload (modern format).
        
        Note: Adaptive Cards are supported in newer Teams versions.
        This is an alternative to MessageCard format.
        
        Args:
            message: Message content
            pdf_filepath: Optional PDF file path
            
        Returns:
            Adaptive Card dictionary
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create card body
        body = [
            {
                "type": "TextBlock",
                "size": "Large",
                "weight": "Bolder",
                "text": "🏥 Cisco Catalyst Center Health Report",
                "wrap": True
            },
            {
                "type": "TextBlock",
                "size": "Small",
                "text": f"Generated: {timestamp}",
                "isSubtle": True,
                "wrap": True
            },
            {
                "type": "TextBlock",
                "text": message[:1000],  # Limit length
                "wrap": True
            }
        ]
        
        # Add PDF note if applicable
        if pdf_filepath:
            import os
            filename = os.path.basename(pdf_filepath) if pdf_filepath else "health_report.pdf"
            body.append({
                "type": "TextBlock",
                "text": f"**📊 PDF Report:** {filename} (saved locally)",
                "wrap": True,
                "color": "Accent"
            })
        
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body
                    }
                }
            ]
        }
        
        return card
