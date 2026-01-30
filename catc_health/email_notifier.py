"""
Email Notification Module

Sends health reports and summaries via SMTP email.
"""

import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import Dict, Any, Optional
from datetime import datetime
import os

from .notification_channel import NotificationChannel


class EmailNotifier(NotificationChannel):
    """Email notification channel implementation using SMTP"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Email notifier.
        
        Args:
            config: Configuration dictionary with SMTP and email settings
        """
        super().__init__(config)
    
    def is_configured(self) -> bool:
        """
        Check if email is properly configured.
        
        Returns:
            True if required email settings are present
        """
        required_fields = ['smtp_server', 'smtp_port', 'email_from', 'email_to']
        return all(self.config.get(field) for field in required_fields)
    
    def validate_config(self) -> tuple[bool, Optional[str]]:
        """
        Validate email configuration.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.config.get("smtp_server"):
            return False, "SMTP_SERVER is not configured"
        
        if not self.config.get("smtp_port"):
            return False, "SMTP_PORT is not configured"
        
        if not self.config.get("email_from"):
            return False, "EMAIL_FROM is not configured"
        
        if not self.config.get("email_to"):
            return False, "EMAIL_TO is not configured"
        
        # Validate port is numeric
        try:
            int(self.config.get("smtp_port"))
        except (ValueError, TypeError):
            return False, "SMTP_PORT must be a valid integer"
        
        return True, None
    
    def send(self, message: str, pdf_filepath: Optional[str] = None) -> bool:
        """
        Send notification via email.
        
        Args:
            message: Message content (text or HTML)
            pdf_filepath: Optional PDF file to attach
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.is_configured():
            is_valid, error = self.validate_config()
            self.logger.error(f"Email not properly configured: {error}")
            return False
        
        try:
            # Create message
            msg = self._create_email_message(message, pdf_filepath)
            
            # Send via SMTP
            self._send_via_smtp(msg)
            
            self.logger.info(f"Email notification sent successfully to {self.config['email_to']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")
            return False
    
    def _create_email_message(self, message: str, pdf_filepath: Optional[str] = None) -> MIMEMultipart:
        """
        Create email message with optional PDF attachment.
        
        Args:
            message: Message content
            pdf_filepath: Optional PDF file path
            
        Returns:
            MIMEMultipart email message
        """
        msg = MIMEMultipart()
        
        # Set headers
        msg['From'] = self.config['email_from']
        msg['To'] = self._format_recipients(self.config['email_to'])
        
        # Add CC if configured
        if self.config.get('email_cc'):
            msg['Cc'] = self._format_recipients(self.config['email_cc'])
        
        # Add BCC if configured (not in headers, but included in send)
        bcc = self._format_recipients(self.config.get('email_bcc', ''))
        
        # Format subject with template support
        msg['Subject'] = self._format_subject()
        
        # Add message body
        html_body = self._format_html_body(message)
        msg.attach(MIMEText(html_body, 'html'))
        
        # Attach PDF if provided
        if pdf_filepath and os.path.exists(pdf_filepath):
            self._attach_pdf(msg, pdf_filepath)
        
        return msg
    
    def _format_recipients(self, recipients: str) -> str:
        """
        Format recipient list from comma-separated string.
        
        Args:
            recipients: Comma-separated email addresses
            
        Returns:
            Formatted recipient string
        """
        if not recipients:
            return ""
        return ', '.join([r.strip() for r in recipients.split(',') if r.strip()])
    
    def _format_subject(self) -> str:
        """
        Format email subject using template.
        
        Returns:
            Formatted subject line
        """
        subject_template = self.config.get('email_subject', 'Catalyst Center Health Report - {date}')
        
        # Replace template variables
        timestamp = datetime.now()
        replacements = {
            '{date}': timestamp.strftime('%Y-%m-%d'),
            '{datetime}': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            '{time}': timestamp.strftime('%H:%M:%S')
        }
        
        subject = subject_template
        for placeholder, value in replacements.items():
            subject = subject.replace(placeholder, value)
        
        return subject
    
    def _format_html_body(self, message: str) -> str:
        """
        Format message as HTML email body.
        
        Args:
            message: Raw message content
            
        Returns:
            HTML formatted email body
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Convert plain text message to HTML paragraphs
        message_html = message.replace('\n\n', '</p><p>').replace('\n', '<br>')
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background-color: #0066cc;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
        }}
        .timestamp {{
            font-size: 14px;
            color: #e0e0e0;
            margin-top: 5px;
        }}
        .content {{
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #0066cc;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 12px;
            color: #666;
        }}
        p {{
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🏥 Cisco Catalyst Center Health Report</h1>
        <div class="timestamp">Generated: {timestamp}</div>
    </div>
    
    <div class="content">
        <p>{message_html}</p>
    </div>
    
    <div class="footer">
        <p>This is an automated health monitoring report from Cisco Catalyst Center.</p>
        <p>For detailed analysis, please refer to the attached PDF report.</p>
    </div>
</body>
</html>
"""
        return html.strip()
    
    def _attach_pdf(self, msg: MIMEMultipart, pdf_filepath: str) -> None:
        """
        Attach PDF file to email message.
        
        Args:
            msg: Email message object
            pdf_filepath: Path to PDF file
        """
        try:
            with open(pdf_filepath, 'rb') as f:
                pdf_attachment = MIMEApplication(f.read(), _subtype='pdf')
            
            filename = os.path.basename(pdf_filepath)
            pdf_attachment.add_header('Content-Disposition', 'attachment', filename=filename)
            msg.attach(pdf_attachment)
            
            self.logger.debug(f"PDF attached: {filename}")
        except Exception as e:
            self.logger.warning(f"Failed to attach PDF: {e}")
    
    def _send_via_smtp(self, msg: MIMEMultipart) -> None:
        """
        Send email message via SMTP server.
        
        Args:
            msg: Prepared email message
            
        Raises:
            Exception: If SMTP send fails
        """
        smtp_server = self.config['smtp_server']
        smtp_port = int(self.config['smtp_port'])
        use_tls = self.config.get('smtp_use_tls', False)
        use_ssl = self.config.get('smtp_use_ssl', False)
        timeout = int(self.config.get('smtp_timeout', 30))
        
        # Collect all recipients
        recipients = [r.strip() for r in self.config['email_to'].split(',') if r.strip()]
        if self.config.get('email_cc'):
            recipients.extend([r.strip() for r in self.config['email_cc'].split(',') if r.strip()])
        if self.config.get('email_bcc'):
            recipients.extend([r.strip() for r in self.config['email_bcc'].split(',') if r.strip()])
        
        # Connect to SMTP server
        if use_ssl:
            smtp = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=timeout)
        else:
            smtp = smtplib.SMTP(smtp_server, smtp_port, timeout=timeout)
        
        try:
            if use_tls and not use_ssl:
                smtp.starttls()
            
            # Authenticate if credentials provided
            if self.config.get('smtp_username') and self.config.get('smtp_password'):
                smtp.login(self.config['smtp_username'], self.config['smtp_password'])
                self.logger.debug("SMTP authentication successful")
            
            # Send email
            smtp.sendmail(self.config['email_from'], recipients, msg.as_string())
            self.logger.debug(f"Email sent to {len(recipients)} recipient(s)")
            
        finally:
            smtp.quit()
