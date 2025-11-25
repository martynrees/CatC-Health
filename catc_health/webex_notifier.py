"""
Webex Notifier Module

Sends health reports to Webex Teams.
"""

import logging
from typing import Dict, Any
from datetime import datetime

try:
    from webexteamssdk import WebexTeamsAPI
    WEBEX_AVAILABLE = True
except ImportError:
    WEBEX_AVAILABLE = False


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
