# Cisco Catalyst Center Health Monitor with AI Analysis

A comprehensive Python script that connects to Cisco Catalyst Center and generates daily health reports for network devices and assurance issues in **PDF format**, with optional **AI-powered analysis** and **Webex Teams integration**.

## Features

- 🔐 **Secure Authentication**: Token-based authentication with Cisco Catalyst Center
- 📊 **Device Health Monitoring**: Retrieves and analyzes device health scores
- ⚠️ **Issue Tracking**: Collects and reports on assurance issues with priority levels
- 📄 **Professional PDF Reports**: Generates detailed PDF reports with tables and summaries
- 🎯 **Health Score Filtering**: Supports filtering by health score thresholds (POOR, FAIR, GOOD)
- 📝 **Comprehensive Logging**: Detailed logging for monitoring and troubleshooting
- 🔧 **Configurable**: Environment-based configuration for different environments
- 🤖 **AI-Powered Analysis**: Optional OpenAI integration for intelligent health summaries
- 📧 **Webex Teams Integration**: Automated messaging and report distribution
- 🩺 **System Health Monitoring**: ISE health, Maglev services, backups, and system updates
- 🏗️ **SDA Fabric Health**: Comprehensive Software-Defined Access fabric monitoring
- 👥 **Client Health Analysis**: Wired and wireless client connectivity monitoring
- 📱 **Application Health**: Network application performance and availability tracking


## Prerequisites

- Python 3.6 or higher
- Access to Cisco Catalyst Center with API permissions
- Network connectivity to your Catalyst Center instance
- **Optional**: OpenAI API key for AI-powered analysis
- **Optional**: Webex Teams bot token and space ID for automated messaging

## Installation

1. **Clone or download the repository:**
   ```bash
   git clone <repository-url>
   cd CatC-Health
   ```

2. **Install dependencies:**
   ```bash
   # Option 1: Install all dependencies (including AI features)
   pip install -r requirements.txt

   # Option 2: Install core dependencies only
   pip install requests urllib3 python-dotenv reportlab

   # Option 3: Install core + AI features separately
   pip install requests urllib3 python-dotenv reportlab
   pip install -r requirements-ai.txt

   # Option 4: Use the installation script
   ./install_dependencies.sh
   ```## Configuration

### Environment Variables (Recommended)

Create a `.env` file in the project directory:

```env
# Required: Catalyst Center Configuration
CATALYST_CENTER_URL=https://your-catalyst-center.example.com
CATALYST_CENTER_USERNAME=your_username
CATALYST_CENTER_PASSWORD=your_password

# Optional: SSL and API Configuration
VERIFY_SSL=false
REQUEST_TIMEOUT=30
DEFAULT_LIMIT=500

# Optional: AI Integration (for --ai-summary feature)
OPENAI_API_KEY=sk-your-openai-api-key-here

# Optional: Webex Teams Integration (for automated messaging)
WEBEX_BOT_TOKEN=your-webex-bot-token-here
WEBEX_SPACE_ID=your-webex-space-id-here

# Optional: Report Configuration
OUTPUT_DIRECTORY=reports
INCLUDE_ALL_DEVICES=true
INCLUDE_GOOD_HEALTH_DEVICES=false

# Optional: Health Filtering
HEALTH_FILTERS=poor,fair
DEVICE_ROLE_FILTERS=
ISSUE_SEVERITY_FILTERS=P1,P2

# Optional: Logging Configuration
LOG_LEVEL=INFO
LOG_TO_FILE=true
LOG_FILE=catalyst_health_monitor.log
```



## Usage

### Basic Health Monitoring

```bash
# Generate standard health report (PDF only)
python3 catalyst_health_monitor.py

# Using the enhanced shell script
./run_health_monitor.sh
```

### AI-Enhanced Health Monitoring

```bash
# Generate health report with AI analysis and Webex messaging
python3 catalyst_health_monitor.py --ai-summary

# Using the enhanced shell script with AI features
./run_health_monitor.sh --ai-summary
```

### Shell Script Features

The `run_health_monitor.sh` script provides enhanced functionality:

- **Automatic Environment Setup**: Creates virtual environment if needed
- **Dependency Validation**: Checks for required and optional packages
- **Configuration Verification**: Validates `.env` file and required variables
- **AI Integration Checks**: Verifies AI dependencies and API keys when using `--ai-summary`
- **Comprehensive Error Reporting**: Detailed troubleshooting guidance
- **Help Documentation**: Built-in help with `--help` or `-h`

```bash
# Show help and usage options
./run_health_monitor.sh --help

# Examples with different modes
./run_health_monitor.sh                    # Standard monitoring
./run_health_monitor.sh --ai-summary       # AI-enhanced with Webex integration
```

### Test Connectivity

Before running the full monitor, test your connection:

```bash
python3 test_connection.py
```


## Output

### PDF Reports

The script creates a `reports/` directory and generates a comprehensive timestamped PDF report:

```
reports/
└── catalyst_health_report_YYYYMMDD_HHMMSS.pdf    # Comprehensive health report
```

The comprehensive report includes:
- **Executive Summary**: Key metrics and overall health status
- **Device Health**: Poor and fair health devices with detailed breakdown
- **Critical Issues**: P1/P2 priority issues requiring immediate attention
- **SDA Fabric Health**: Software-Defined Access fabric site health
- **Application Health**: Poor and fair performing applications
- **Client Health**: Wired and wireless client connectivity issues
- **System Health**: ISE nodes, Maglev services, backups, and system updates

### AI Analysis Output (with --ai-summary)

When using the `--ai-summary` flag, additional outputs include:

1. **Console AI Summary**: Intelligent analysis displayed in the terminal
2. **Webex Teams Message**: Automated message sent to configured Webex space with:
   - AI-generated health summary
   - PDF report attachment
   - Timestamp and executive overview

### Log Files

- `catalyst_health_monitor.log`: Detailed execution logs with API calls and errors

## Automation

### Cron Job Setup

To run daily at 6 AM:

```bash
# Edit crontab
crontab -e

# Add this line for standard monitoring:
0 6 * * * /path/to/CatC-Health/run_health_monitor.sh

# Add this line for AI-enhanced monitoring:
0 6 * * * /path/to/CatC-Health/run_health_monitor.sh --ai-summary
```

### Systemd Timer (Linux)

Create a systemd service and timer for more advanced scheduling.

**Example service file** (`/etc/systemd/system/catalyst-health.service`):
```ini
[Unit]
Description=Cisco Catalyst Center Health Monitor
After=network.target

[Service]
Type=oneshot
User=your-user
WorkingDirectory=/path/to/CatC-Health
ExecStart=/path/to/CatC-Health/run_health_monitor.sh --ai-summary
```

**Example timer file** (`/etc/systemd/system/catalyst-health.timer`):
```ini
[Unit]
Description=Run Catalyst Health Monitor daily
Requires=catalyst-health.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

## API Endpoints Used

### Authentication
- `/dna/system/api/v1/auth/token` - Token-based authentication

### Device and Network Health
- `/dna/intent/api/v1/device-health` - Device health information
- `/dna/data/api/v1/networkDevices` - Network device inventory

### Issues and Monitoring
- `/dna/data/api/v1/assuranceIssues` - Current assurance issues
- `/dna/intent/api/v1/issues` - Intent API issues (P1/P2 priority)

### Sites and Fabric
- `/dna/intent/api/v1/sites` - Site hierarchy information
- `/dna/intent/api/v1/sda/fabricSites` - SDA fabric sites
- `/dna/data/api/v1/fabricSiteHealthSummaries` - Fabric site health data

### Applications and Clients
- `/dna/intent/api/v1/application-health` - Application health status
- `/dna/data/api/v1/networkApplications` - Network application metrics
- `/dna/intent/api/v1/client-health` - Client health information
- `/dna/data/api/v1/clients` - Detailed client data

### System Health (Internal APIs)
- `/api/v1/system/health/cisco-ise` - ISE integration health
- `/api/system/v1/maglev/services/summary` - Maglev services status
- `/api/system/v1/maglev/backup` - System backup information
- `/api/system/v1/maglev/backup/history` - Backup history
- `/api/system/v1/systemupdater/common/availabe_update_info` - System updates

## Health Score Interpretation

- **POOR (0-3)**: Devices requiring immediate attention
- **FAIR (4-7)**: Devices with moderate issues that should be monitored
- **GOOD (8-10)**: Devices operating normally

## AI Features

### AI-Powered Analysis
When using the `--ai-summary` flag, the system provides:

- **Intelligent Health Assessment**: OpenAI GPT-4o-mini analyzes all health data
- **Expert System Prompt**: Configured with Cisco Catalyst Center expertise
- **Critical Issue Identification**: Highlights urgent issues requiring immediate attention
- **Actionable Recommendations**: Provides specific next steps for network engineers
- **Trend Analysis**: Identifies patterns and performance trends

### Webex Teams Integration
- **Automated Messaging**: Sends AI summaries to configured Webex spaces
- **PDF Attachments**: Includes detailed reports for comprehensive analysis
- **Rich Formatting**: Markdown-formatted messages with timestamps
- **Bot Authentication**: Uses Webex Teams SDK with bot tokens

### Error Handling
The AI integration includes specific error messages for common scenarios:
- Missing API key: `"❌ AI Summary Error: The summary was not able to be processed as the API key was not provided."`
- Quota exceeded: `"❌ AI Summary Error: The summary was not able to be processed as the API quota was exceeded."`
- API unavailable: `"❌ AI Summary Error: The summary was not able to be processed as the API was not available."`

## Dependencies

### Core Dependencies (Required)
- `requests>=2.25.0` - HTTP client for API calls
- `urllib3>=1.26.0` - HTTP library with SSL support
- `python-dotenv>=0.19.0` - Environment variable management
- `reportlab>=3.6.0` - PDF generation library

### Optional AI Dependencies
- `langchain>=0.1.0` - AI framework for structured LLM interactions
- `langchain-openai>=0.1.0` - OpenAI integration for LangChain

### Optional Webex Dependencies
- `webexteamssdk>=1.6.0` - Webex Teams API integration

**Note**: The script gracefully handles missing optional dependencies and will continue to function without AI features if these packages are not installed.

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify credentials in `.env` file
   - Check network connectivity to Catalyst Center
   - Ensure API access is enabled for your user account
   - Confirm Catalyst Center URL is correct (include https://)

2. **SSL Certificate Errors**
   - Set `VERIFY_SSL=false` in `.env` for self-signed certificates
   - For production, use valid certificates and set `VERIFY_SSL=true`

3. **Import/Dependency Errors**
   - Run `pip install -r requirements.txt` to install required packages
   - For AI features: `pip install -r requirements-ai.txt`
   - Use the installation script: `./install_dependencies.sh`
   - Ensure Python 3.6+ is being used

4. **Shell Script Issues**
   - Make sure the script is executable: `chmod +x run_health_monitor.sh`
   - Check virtual environment creation with `./install_dependencies.sh`
   - Use `./run_health_monitor.sh --help` for usage guidance
   - Review script output for specific dependency or configuration issues

4. **AI Features Not Working**
   - Check if `OPENAI_API_KEY` is set in `.env` file
   - Verify OpenAI API key is valid and has sufficient quota
   - Install AI dependencies: `pip install langchain langchain-openai`
   - Review AI error messages in console output

5. **Webex Messages Not Sent**
   - Verify `WEBEX_BOT_TOKEN` and `WEBEX_SPACE_ID` in `.env` file
   - Ensure bot has access to the specified Webex space
   - Install Webex SDK: `pip install webexteamssdk`
   - Check bot permissions in Webex Teams

6. **Empty or Incomplete Reports**
   - Check if devices are registered in Catalyst Center
   - Verify user permissions for device and assurance data access
   - Review API endpoint connectivity (some internal APIs may require elevated access)
   - Check log files for specific API call failures

7. **Performance Issues**
   - Adjust `DEFAULT_LIMIT` in `.env` to reduce API response sizes
   - Increase `REQUEST_TIMEOUT` for slow network connections
   - Use health filters to limit data collection scope

8. **Shell Script Troubleshooting**
   - The enhanced `run_health_monitor.sh` provides built-in diagnostics
   - Use `./run_health_monitor.sh --help` for usage information
   - Review script output for environment validation results
   - Check virtual environment activation and dependency installation

### Logging

The script generates detailed logs in `catalyst_health_monitor.log`:

```bash
# View recent logs
tail -f catalyst_health_monitor.log

# Search for errors
grep ERROR catalyst_health_monitor.log
```

## Security Notes

- Store credentials securely using environment variables
- Consider using API keys instead of passwords where possible
- Use HTTPS and verify SSL certificates in production
- Regularly rotate credentials
- Limit API user permissions to read-only access

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs for error details
3. Open an issue with relevant log excerpts and configuration details (redacted)
