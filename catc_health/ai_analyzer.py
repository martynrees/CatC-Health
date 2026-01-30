"""
AI Health Analyzer Module

AI-powered health analysis using multiple AI providers (OpenAI, Google, Anthropic).
"""

import logging
import re
from typing import Dict, Any, Optional
from datetime import datetime

# Try importing AI provider libraries
OPENAI_AVAILABLE = False
GOOGLE_AVAILABLE = False
ANTHROPIC_AVAILABLE = False

try:
    from langchain_openai import ChatOpenAI
    from langchain.schema import HumanMessage, SystemMessage
    OPENAI_AVAILABLE = True
except ImportError:
    pass

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    GOOGLE_AVAILABLE = True
except ImportError:
    pass

try:
    from langchain_anthropic import ChatAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    pass

# At least one provider must be available
LANGCHAIN_AVAILABLE = OPENAI_AVAILABLE or GOOGLE_AVAILABLE or ANTHROPIC_AVAILABLE


def sanitize_for_ai(text: str, max_length: int = 5000) -> str:
    """
    Sanitize text data before sending to AI to prevent prompt injection.
    
    Args:
        text: The text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text safe for AI prompts
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Remove control characters and normalize whitespace
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    
    # Normalize multiple whitespace to single space
    text = re.sub(r'\s+', ' ', text)
    
    # Truncate to max length
    if len(text) > max_length:
        text = text[:max_length] + "... [truncated]"
    
    return text.strip()


class AIHealthAnalyzer:
    """AI-powered health analysis using multiple AI providers"""
    
    # Model mappings for each provider (cost-effective options)
    PROVIDER_MODELS = {
        # Updated to GPT-5-nano (43% cheaper, better performance)
        "openai": "gpt-5-nano",
        "google": "gemini-1.5-flash",
        "anthropic": "claude-3-haiku-20240307"
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the AI analyzer

        Args:
            config: AI configuration dictionary
        """
        self.config = config
        self.logger = self._setup_logging()
        self.provider = config.get("provider", "openai").lower()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(f"{__name__}.AIHealthAnalyzer")
        logger.setLevel(logging.INFO)
        return logger
    
    def _create_ai_model(self):
        """
        Create AI model based on configured provider
        
        Returns:
            LangChain chat model instance
            
        Raises:
            ValueError: If provider is not supported or dependencies are missing
        """
        provider = self.provider
        
        # Validate provider
        if provider not in self.PROVIDER_MODELS:
            raise ValueError(f"Unsupported AI provider: {provider}. Must be one of: openai, google, anthropic")
        
        # OpenAI provider
        if provider == "openai":
            if not OPENAI_AVAILABLE:
                raise ImportError("OpenAI provider requires: pip install langchain-openai")
            
            api_key = self.config.get("openai_api_key")
            if not api_key:
                raise ValueError("OPENAI_API_KEY not configured in .env file")
            
            self.logger.info(
                "Using OpenAI provider (gpt-5-nano)"
            )
            return ChatOpenAI(
                model=self.PROVIDER_MODELS["openai"],
                api_key=api_key,
                temperature=0.1,
                timeout=60,
                max_retries=2
            )
        
        # Google Gemini provider
        elif provider == "google":
            if not GOOGLE_AVAILABLE:
                raise ImportError("Google provider requires: pip install langchain-google-genai")
            
            api_key = self.config.get("google_api_key")
            if not api_key:
                raise ValueError("GOOGLE_API_KEY not configured in .env file")
            
            self.logger.info(
                "Using Google Gemini provider (gemini-1.5-flash)"
            )
            return ChatGoogleGenerativeAI(
                model=self.PROVIDER_MODELS["google"],
                google_api_key=api_key,
                temperature=0.1,
                timeout=60,
                max_retries=2
            )
        
        # Anthropic Claude provider
        elif provider == "anthropic":
            if not ANTHROPIC_AVAILABLE:
                raise ImportError("Anthropic provider requires: pip install langchain-anthropic")
            
            api_key = self.config.get("anthropic_api_key")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not configured in .env file")
            
            self.logger.info(
                "Using Anthropic Claude provider (claude-3-haiku)"
            )
            return ChatAnthropic(
                model=self.PROVIDER_MODELS["anthropic"],
                anthropic_api_key=api_key,
                temperature=0.1,
                timeout=60,
                max_retries=2
            )

    def analyze_health_data(self, health_data: Dict[str, Any]) -> str:
        """
        Analyze health data using configured AI provider and return a summary

        Args:
            health_data: Dictionary containing all health data from the monitoring

        Returns:
            Summary string or error message
        """
        if not LANGCHAIN_AVAILABLE:
            return "❌ AI Summary Error: LangChain dependencies not installed. Please install: pip install langchain langchain-openai (or langchain-google-genai, langchain-anthropic)"

        try:
            # Create AI model using factory function
            llm = self._create_ai_model()
            
            # Prepare the health data summary for analysis
            data_summary = self._prepare_data_summary(health_data)
            
            # Sanitize the data summary to prevent prompt injection
            data_summary = sanitize_for_ai(data_summary, max_length=8000)

            # Create messages
            system_message = SystemMessage(content=self.config["system_prompt"])
            human_message = HumanMessage(content=f"""
Please analyze the following Cisco Catalyst Center health data and provide a concise summary with urgent call-outs:

{data_summary}

Please provide:
1. Overall network health status
2. Critical issues requiring immediate attention
3. Key recommendations for the network engineer
4. Any trends or patterns noticed

Keep the summary concise but comprehensive for quick decision making.
""")

            # Get AI response
            provider_name = self.provider.upper()
            self.logger.info(f"Sending health data to {provider_name} for analysis...")
            response = llm.invoke([system_message, human_message])

            summary = response.content.strip()
            self.logger.info(f"AI analysis completed successfully using {provider_name}")
            return summary

        except (ValueError, ImportError) as e:
            # Configuration or dependency errors
            error_msg = str(e)
            self.logger.error(f"AI configuration error: {error_msg}")
            return f"❌ AI Summary Error: {error_msg}"
        
        except Exception as e:
            error_msg = str(e).lower()
            provider_name = self.provider.upper()
            
            if "quota" in error_msg or "rate limit" in error_msg:
                return f"❌ AI Summary Error: {provider_name} API quota exceeded or rate limit reached."
            elif "api" in error_msg and ("unavailable" in error_msg or "connection" in error_msg):
                return f"❌ AI Summary Error: {provider_name} API is unavailable or connection failed."
            elif "timeout" in error_msg or "timed out" in error_msg:
                return f"❌ AI Summary Error: {provider_name} API request timed out. The API may be slow or unresponsive."
            elif "authentication" in error_msg or "api key" in error_msg or "api_key" in error_msg:
                return f"❌ AI Summary Error: {provider_name} API authentication failed. Check your API key."
            else:
                self.logger.error(f"AI analysis failed: {e}")
                return f"❌ AI Summary Error: Failed to process health data analysis with {provider_name}. Error: {str(e)}"

    def _prepare_data_summary(self, health_data: Dict[str, Any]) -> str:
        """
        Prepare a formatted summary of the health data for AI analysis

        Args:
            health_data: Raw health data dictionary

        Returns:
            Formatted string summary
        """
        summary_parts = []

        # Device Health Summary
        devices = health_data.get('all_devices', [])
        if devices:
            total_devices = len(devices)
            poor_devices = len([d for d in devices if d.get('overallHealth', 0) <= 3])
            fair_devices = len([d for d in devices if 3 < d.get('overallHealth', 0) <= 7])
            good_devices = len([d for d in devices if d.get('overallHealth', 0) > 7])

            summary_parts.append(f"""
DEVICE HEALTH SUMMARY:
- Total Devices: {total_devices}
- Poor Health (≤3): {poor_devices} ({(poor_devices/max(total_devices,1)*100):.1f}%)
- Fair Health (4-7): {fair_devices} ({(fair_devices/max(total_devices,1)*100):.1f}%)
- Good Health (>7): {good_devices} ({(good_devices/max(total_devices,1)*100):.1f}%)
""")

            # Add device details for poor health devices
            if poor_devices > 0:
                poor_device_details = []
                for device in devices:
                    if device.get('overallHealth', 0) <= 3:
                        poor_device_details.append(f"  - {device.get('name', 'Unknown')} (IP: {device.get('ipAddress', 'N/A')}, Health: {device.get('overallHealth', 'N/A')})")

                if poor_device_details:
                    summary_parts.append("CRITICAL DEVICES REQUIRING ATTENTION:")
                    summary_parts.extend(poor_device_details[:10])  # Limit to top 10
                    if len(poor_device_details) > 10:
                        summary_parts.append(f"  ... and {len(poor_device_details) - 10} more devices")

        # Issues Summary
        issues = health_data.get('issues', [])
        if issues:
            p1_issues = [i for i in issues if i.get('priority') == 'P1']
            p2_issues = [i for i in issues if i.get('priority') == 'P2']

            summary_parts.append(f"""
CRITICAL ISSUES SUMMARY:
- P1 (Critical) Issues: {len(p1_issues)}
- P2 (High Priority) Issues: {len(p2_issues)}
""")

            # Add critical issue details
            if p1_issues:
                summary_parts.append("P1 CRITICAL ISSUES:")
                for issue in p1_issues[:5]:  # Top 5 critical issues
                    summary_parts.append(f"  - {issue.get('name', 'Unknown Issue')}")

        # Fabric Health Summary
        fabric_health = health_data.get('fabric_health', [])
        if fabric_health:
            critical_sites = [s for s in fabric_health if s.get('goodHealthPercentage', 0) < 50]
            warning_sites = [s for s in fabric_health if 50 <= s.get('goodHealthPercentage', 0) < 80]

            summary_parts.append(f"""
SDA FABRIC HEALTH:
- Total Fabric Sites: {len(fabric_health)}
- Critical Sites (<50% health): {len(critical_sites)}
- Warning Sites (50-79% health): {len(warning_sites)}
""")

            if critical_sites:
                summary_parts.append("CRITICAL FABRIC SITES:")
                for site in critical_sites:
                    summary_parts.append(f"  - {site.get('name', 'Unknown Site')} ({site.get('goodHealthPercentage', 0):.1f}% health)")

        # Client Health Summary
        clients = health_data.get('clients', [])
        if clients:
            poor_clients = len([c for c in clients if self._categorize_client_health(c.get('health', {}).get('overallScore', 0)) == 'POOR'])

            summary_parts.append(f"""
CLIENT HEALTH:
- Total Clients: {len(clients)}
- Poor Health Clients: {poor_clients}
""")

        # System Health Summary
        ise_health = health_data.get('ise_health', [])
        maglev_services = health_data.get('maglev_services', [])
        system_backup = health_data.get('system_backup', [])

        if ise_health or maglev_services or system_backup:
            available_ise = len([n for n in ise_health if n.get('status') == 'AVAILABLE'])
            running_services = len([s for s in maglev_services if s.get('status') == 'running'])
            successful_backups = len([b for b in system_backup if b.get('status') == 'SUCCESS'])

            summary_parts.append(f"""
SYSTEM HEALTH:
- ISE Nodes Available: {available_ise}/{len(ise_health)}
- Maglev Services Running: {running_services}/{len(maglev_services)}
- Successful Backups: {successful_backups}/{len(system_backup)}
""")

        return "\n".join(summary_parts)

    def _categorize_client_health(self, health_score: Any) -> str:
        """Categorize client health based on health score"""
        if not isinstance(health_score, (int, float)):
            return 'UNKNOWN'
        if health_score < 4:
            return 'POOR'
        elif health_score < 7:
            return 'FAIR'
        else:
            return 'GOOD'
