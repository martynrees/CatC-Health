# Cisco Catalyst Center Health Monitor with AI Analysis

A modular Python application that connects to Cisco Catalyst Center and generates daily health reports for network devices and assurance issues in **PDF format**, with optional **AI-powered analysis** and **multi-channel notifications** (Email, Webex Teams, MS Teams).

## Architecture

The application uses a modular package structure for improved maintainability and testability:

- **`catc_health/`** - Core package with specialized modules:
  - `client.py` - API client with automatic retry logic and context manager support
  - `config.py` - Configuration management and validation
  - `ai_analyzer.py` - OpenAI GPT-4o-mini integration
  - `notification_channel.py` - Abstract base class for notifications
  - `webex_notifier.py` - Webex Teams messaging
  - `email_notifier.py` - SMTP email notifications
  - `teams_notifier.py` - Microsoft Teams webhook integration
  - `notification_manager.py` - Multi-channel notification orchestration
  - `report_generator.py` - PDF report generation
  - `api_adapter.py` - API field normalization
  - `utils.py` - Shared utilities
- **`catalyst_health_monitor.py`** - Main entry point (483 lines)
- **`tests/`** - Unit test suite with pytest

## Features

- 🔐 **Secure Authentication**: Token-based authentication with Cisco Catalyst Center
- 🔄 **Automatic Retry Logic**: Tenacity-based retry with exponential backoff for API resilience
- 📊 **Device Health Monitoring**: Retrieves and analyzes device health scores
- ⚠️ **Issue Tracking**: Collects and reports on assurance issues with priority levels
- 📄 **Professional PDF Reports**: Generates detailed PDF reports with tables and summaries
- 🎯 **Health Score Filtering**: Supports filtering by health score thresholds (POOR, FAIR, GOOD)
- 📝 **Comprehensive Logging**: Detailed logging for monitoring and troubleshooting
- 🔧 **Configurable**: Environment-based configuration with validation
- 🤖 **AI-Powered Analysis**: Optional OpenAI GPT-4o-mini integration for intelligent health summaries
- 📧 **Multi-Channel Notifications**: Flexible notification delivery via Email, Webex Teams, and MS Teams
  - **Email (SMTP)**: Full-featured HTML emails with PDF attachments, TLS/SSL support
  - **Webex Teams**: Bot-based messaging with file uploads
  - **Microsoft Teams**: Webhook-based MessageCard notifications
  - **Independent Channels**: Enable/disable channels individually via .env or CLI
  - **CLI Overrides**: Command-line flags override .env defaults for one-time runs
  - **Graceful Degradation**: Channels fail independently without affecting others
- 🩺 **System Health Monitoring**: ISE health, Maglev services, backups, and system updates
- 🏗️ **SDA Fabric Health**: Comprehensive Software-Defined Access fabric monitoring
- 👥 **Client Health Analysis**: Wired and wireless client connectivity monitoring
- 📱 **Application Health**: Network application performance and availability tracking
- 🔀 **API Version Compatibility**: Automatic field normalization across API versions
- ✅ **Unit Tested**: Pytest-based test suite for reliability


## Prerequisites

- Python 3.8 or higher
- Access to Cisco Catalyst Center with API permissions
- Network connectivity to your Catalyst Center instance
- **Optional**: OpenAI API key for AI-powered analysis
- **Optional**: SMTP server access for email notifications
- **Optional**: Webex Teams bot token and space ID for Webex notifications
- **Optional**: Microsoft Teams incoming webhook URL for Teams notifications

## Installation

1. **Clone or download the repository:**
   ```bash
   git clone <repository-url>
   cd CatC-Health
   ```

2. **Install dependencies:**
   ```bash
   # Install all dependencies including AI features (recommended)
   pip install -r requirements.txt

   # Alternative: Install only AI-specific dependencies
   pip install -r requirements-ai.txt

   # Alternative: Use the installation script
   ./install_dependencies.sh
   ```

3. **Configure environment:**
   ```bash
   # Copy the example configuration
   cp .env.example .env

   # Edit .env with your credentials
   nano .env
   ```## Configuration

### Environment Variables

The application requires a `.env` file for configuration. Use `.env.example` as a template:

```bash
cp .env.example .env
```

**Required Variables:**
```env
# Catalyst Center Configuration
CATALYST_CENTER_URL=https://your-catalyst-center.example.com
CATALYST_CENTER_USERNAME=your_username
CATALYST_CENTER_PASSWORD=your_password
```

**Optional Variables:**
```env
# SSL and API Configuration
VERIFY_SSL=false
REQUEST_TIMEOUT=30
DEFAULT_LIMIT=500

# AI Integration (for --ai-summary feature)
OPENAI_API_KEY=sk-your-openai-api-key-here

# =====================================================
# NOTIFICATION CHANNELS (All Optional)
# =====================================================
# Enable/disable individual notification channels
# CLI flags (--notify-email, --notify-webex, --notify-teams) override these

# Webex Teams Notifications
ENABLE_WEBEX_NOTIFICATIONS=false
WEBEX_BOT_TOKEN=your-webex-bot-token-here
WEBEX_SPACE_ID=your-webex-space-id-here

# Email Notifications (SMTP)
ENABLE_EMAIL_NOTIFICATIONS=false
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USE_TLS=true
EMAIL_USE_SSL=false
EMAIL_USERNAME=your-email@example.com
EMAIL_PASSWORD=your-app-password-here
EMAIL_FROM=catalyst-monitor@example.com
EMAIL_TO=admin@example.com
EMAIL_CC=                                      # Optional: comma-separated
EMAIL_BCC=                                     # Optional: comma-separated
EMAIL_SUBJECT=Catalyst Center Health Report - {timestamp}

# Microsoft Teams Notifications (Incoming Webhook)
ENABLE_TEAMS_NOTIFICATIONS=false
TEAMS_WEBHOOK_URL=https://your-org.webhook.office.com/webhookb2/...

# Report Configuration
OUTPUT_DIRECTORY=reports
INCLUDE_ALL_DEVICES=true
INCLUDE_GOOD_HEALTH_DEVICES=false

# Health Filtering
HEALTH_FILTERS=poor,fair
DEVICE_ROLE_FILTERS=
ISSUE_SEVERITY_FILTERS=P1,P2

# Logging Configuration
LOG_LEVEL=INFO
LOG_TO_FILE=true
LOG_FILE=catalyst_health_monitor.log
```

**Configuration Validation:**

The application validates your configuration on startup and will report:
- Missing `.env` file
- Missing required variables (URL, username, password)
- Invalid or unreachable Catalyst Center URL

**Security Note:** The `.env` file is automatically excluded from git tracking. Never commit credentials to version control.

### Notification Channel Setup

#### Email Notifications (SMTP)

Configure SMTP settings in your `.env` file:

```env
ENABLE_EMAIL_NOTIFICATIONS=true
EMAIL_SMTP_SERVER=smtp.gmail.com          # Your SMTP server
EMAIL_SMTP_PORT=587                       # 587 for TLS, 465 for SSL, 25 for unencrypted
EMAIL_USE_TLS=true                        # Use TLS (recommended for port 587)
EMAIL_USE_SSL=false                       # Use SSL (for port 465)
EMAIL_USERNAME=your-email@example.com     # SMTP authentication username
EMAIL_PASSWORD=your-app-password          # SMTP password or app-specific password
EMAIL_FROM=catalyst-monitor@example.com   # Sender address
EMAIL_TO=admin@example.com                # Recipient address
EMAIL_SUBJECT=Catalyst Center Health Report - {timestamp}
```

**Popular SMTP Providers:**
- **Gmail**: `smtp.gmail.com:587` (requires app-specific password)
- **Office 365**: `smtp.office365.com:587`
- **SendGrid**: `smtp.sendgrid.net:587`
- **Custom**: Your organization's SMTP relay

#### Webex Teams Notifications

1. Create a Webex bot at [developer.webex.com](https://developer.webex.com)
2. Get the bot token and add the bot to your Webex space
3. Get the space ID (from space settings or API)
4. Configure in `.env`:

```env
ENABLE_WEBEX_NOTIFICATIONS=true
WEBEX_BOT_TOKEN=your-webex-bot-token-here
WEBEX_SPACE_ID=your-webex-space-id-here
```

#### Microsoft Teams Notifications

1. In your Teams channel, click **⋯ More options** → **Connectors**
2. Search for "Incoming Webhook" and click **Configure**
3. Give it a name (e.g., "Catalyst Health Monitor") and copy the webhook URL
4. Configure in `.env`:

```env
ENABLE_TEAMS_NOTIFICATIONS=true
TEAMS_WEBHOOK_URL=https://your-org.webhook.office.com/webhookb2/...
```

**Note:** Teams webhooks cannot receive file attachments, so the PDF report location is mentioned in the message.



## Usage

### Basic Health Monitoring

```bash
# Generate standard health report (PDF only, no notifications)
python3 catalyst_health_monitor.py

# Using the shell script
./run_health_monitor.sh
```

### AI-Enhanced Analysis

```bash
# Generate AI-powered analysis and summary
python3 catalyst_health_monitor.py --ai-summary

# Using the shell script
./run_health_monitor.sh --ai-summary
```

### Notification Options

The notification system is flexible and supports multiple channels:

```bash
# Send notification via email (uses configured .env settings)
python3 catalyst_health_monitor.py --notify-email

# Send to multiple channels
python3 catalyst_health_monitor.py --notify-email --notify-webex --notify-teams

# AI analysis with notifications
python3 catalyst_health_monitor.py --ai-summary --notify-email

# AI analysis without notifications (console only)
python3 catalyst_health_monitor.py --ai-summary --no-notifications

# Use shell script with notification flags
./run_health_monitor.sh --notify-webex --notify-teams
```

**CLI Flags:**
- `--ai-summary`: Enable AI-powered health analysis
- `--notify-email`: Send notifications via Email (overrides .env)
- `--notify-webex`: Send notifications via Webex Teams (overrides .env)
- `--notify-teams`: Send notifications via MS Teams (overrides .env)
- `--no-notifications`: Disable all notifications (overrides .env)

**How It Works:**
1. **Default behavior** (.env not configured): PDF report only, no notifications
2. **With .env configuration**: Channels enabled in .env send automatically
3. **With CLI flags**: CLI flags override .env settings for one-time runs
4. **AI is optional**: Notifications work with or without AI summaries
5. **Independent channels**: One channel failing doesn't affect others

### Shell Script Features

The `run_health_monitor.sh` script provides enhanced functionality:

- **Automatic Environment Setup**: Creates virtual environment if needed
- **Dependency Validation**: Checks for required and optional packages
- **Configuration Verification**: Validates `.env` file and required variables
- **Channel Status Checks**: Reports which notification channels are configured
- **Comprehensive Error Reporting**: Detailed troubleshooting guidance
- **Help Documentation**: Built-in help with `--help` or `-h`

```bash
# Show help and all available options
./run_health_monitor.sh --help

# Examples from help text
./run_health_monitor.sh                                  # Standard report only
./run_health_monitor.sh --ai-summary                     # AI analysis + default notifications
./run_health_monitor.sh --notify-email                   # Email notification (PDF only)
./run_health_monitor.sh --ai-summary --notify-email      # AI analysis + email
./run_health_monitor.sh --notify-webex --notify-teams    # Multi-channel notifications
```

## Testing

Run the unit test suite to verify the installation:

```bash
# Run all tests
pytest tests/ -v

# Run tests with coverage report
pytest tests/ --cov=catc_health --cov-report=term-missing

# Run specific test file
pytest tests/test_health_monitor.py -v
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

### Notification Output

When notifications are enabled, the system sends health reports through configured channels:

#### Email Notifications
- **HTML-formatted email** with professional styling
- **PDF report attached** as `catalyst_health_report_YYYYMMDD_HHMMSS.pdf`
- **AI summary included** (if --ai-summary enabled) or basic health summary
- **Device and issue counts** with health score breakdown
- **Supports TLS/SSL** for secure SMTP connections
- **CC/BCC support** for distribution lists

#### Webex Teams Notifications
- **Markdown-formatted message** posted to configured space
- **PDF report uploaded** and attached to the message
- **AI summary or basic summary** included in message text
- **Timestamp and metrics** for quick reference

#### Microsoft Teams Notifications
- **MessageCard format** with rich formatting and colors
- **Health metrics section** with device counts and issues
- **PDF report location referenced** (Teams webhooks can't upload files)
- **AI summary or basic summary** included in card text
- **Actionable facts** section with key statistics

**Message Content:**
- **With AI** (`--ai-summary`): Intelligent OpenAI-generated health analysis
- **Without AI**: Basic summary with device counts, issue counts, and health breakdown
- All channels work independently and can be mixed and matched

### AI Analysis Output (with --ai-summary)

When using the `--ai-summary` flag, additional outputs include:

1. **Console AI Summary**: Intelligent analysis displayed in the terminal
2. **Enhanced Notifications**: AI-generated summaries sent to all enabled channels
   - Webex Teams: AI summary with PDF attachment
   - Email: AI summary in HTML email body with PDF
   - MS Teams: AI summary in MessageCard with PDF reference

### Log Files

- `catalyst_health_monitor.log`: Detailed execution logs with API calls, errors, and notification delivery status

## Automation

### Cron Job Setup

To run daily at 6 AM:

```bash
# Edit crontab
crontab -e

# Standard monitoring with PDF only
0 6 * * * /path/to/CatC-Health/run_health_monitor.sh

# AI-enhanced with default notification channels (.env)
0 6 * * * /path/to/CatC-Health/run_health_monitor.sh --ai-summary

# Email notifications only (override .env)
0 6 * * * /path/to/CatC-Health/run_health_monitor.sh --ai-summary --notify-email

# Multi-channel notifications
0 6 * * * /path/to/CatC-Health/run_health_monitor.sh --notify-email --notify-webex --notify-teams
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
ExecStart=/path/to/CatC-Health/run_health_monitor.sh --ai-summary --notify-email
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
- `/api/system/v1/systemupdater/common/available_update_info` - System updates
- `/dna/intent/api/v1/eox-status/device` - End of Life (EoX) status
- `/dna/intent/api/v1/compliance/detail` - Device compliance details
- `/dna/intent/api/v1/image/importation/golden` - Golden image information
- `/dna/intent/api/v1/image/importation/device-family-identifiers` - Device family identifiers

## Health Score Interpretation

- **POOR (≤3)**: Devices requiring immediate attention
- **FAIR (4-6)**: Devices with moderate issues that should be monitored
- **GOOD (≥7)**: Devices operating normally

## AI Features

### AI-Powered Analysis
When using the `--ai-summary` flag, the system provides:

- **Intelligent Health Assessment**: OpenAI GPT-4o-mini analyzes all health data
- **Expert System Prompt**: Configured with Cisco Catalyst Center expertise
- **Critical Issue Identification**: Highlights urgent issues requiring immediate attention
- **Actionable Recommendations**: Provides specific next steps for network engineers
- **Trend Analysis**: Identifies patterns and performance trends
- **Flexible Delivery**: AI summaries can be viewed in console or sent via notifications

## Notification System

### Architecture
The notification system uses a modular, channel-based architecture:

- **Abstract Base Class**: `NotificationChannel` defines the interface
- **Independent Channels**: Email, Webex, and Teams operate independently
- **Notification Manager**: Orchestrates multi-channel delivery
- **Graceful Degradation**: One channel failing doesn't affect others
- **Flexible Configuration**: Enable/disable channels via .env or CLI

### Email (SMTP)
- **Full-featured HTML emails** with professional styling and branding
- **PDF attachments** for comprehensive reports
- **TLS/SSL support** for secure connections
- **Authentication** with username/password or app-specific passwords
- **CC/BCC support** for distribution lists
- **Template system** with {timestamp} and health data variables

**Supported SMTP servers**: Gmail, Office 365, SendGrid, custom SMTP relays

### Webex Teams
- **Bot-based integration** using Webex Teams SDK
- **File uploads** - PDF reports attached to messages
- **Markdown formatting** for rich text presentation
- **Space targeting** - send to specific Webex spaces
- **Backward compatible** with existing configurations

### Microsoft Teams
- **Incoming webhooks** - no app registration required
- **MessageCard format** with rich formatting and colors
- **Adaptive Cards support** (alternative format)
- **Health metrics section** with structured facts
- **PDF reference** (webhooks cannot upload files directly)

### Error Handling
All notification channels gracefully degrade if:
- Configuration is missing or invalid
- Network connectivity issues occur
- API quota is exceeded
- Authentication fails
- Services are unavailable

**Per-channel status reporting** shows which channels succeeded/failed independently.

Specific error messages guide users to resolve configuration issues.

## Dependencies

All dependencies are managed in `requirements.txt`:

### Core Dependencies
- `requests>=2.25.0` - HTTP client for API calls
- `urllib3>=1.26.0` - HTTP library with SSL support
- `python-dotenv>=0.19.0` - Environment variable management
- `reportlab>=3.6.0` - PDF generation library
- `tenacity>=8.2.0` - Retry logic with exponential backoff

### AI and Notification Dependencies (Optional)
- `langchain>=0.1.0` - AI framework for structured LLM interactions
- `langchain-openai>=0.1.0` - OpenAI GPT-4o-mini integration
- `webexteamssdk>=1.6.0` - Webex Teams API integration

**Note**: Email and Teams notifications use built-in Python libraries and `requests` (already a core dependency), so no additional packages are required for those channels.

### Testing Dependencies
- `pytest>=7.4.0` - Unit testing framework
- `pytest-cov>=4.1.0` - Code coverage reporting

**Graceful Degradation**: The application detects missing optional dependencies at runtime:
- Without `langchain`/`langchain-openai`: The `--ai-summary` flag will display an error message but the PDF report will still generate
- Without `webexteamssdk`: Webex notifications will be skipped with a warning
- Email and Teams notifications work without additional dependencies
- The application will never crash due to missing optional dependencies

## Troubleshooting

### Common Issues

1. **Configuration Validation Errors**
   - Run the application to see specific validation errors
   - Ensure `.env` file exists (copy from `.env.example`)
   - Verify all required variables are set: `CATALYST_CENTER_URL`, `CATALYST_CENTER_USERNAME`, `CATALYST_CENTER_PASSWORD`
   - Check that Catalyst Center URL includes `https://`

2. **Authentication Failures**
   - Verify credentials in `.env` file are correct
   - Check network connectivity to Catalyst Center
   - Ensure API access is enabled for your user account
   - Confirm the URL points to the correct Catalyst Center instance

3. **SSL Certificate Errors**
   - Set `VERIFY_SSL=false` in `.env` for self-signed certificates
   - For production, use valid certificates and set `VERIFY_SSL=true`

4. **API Request Failures**
   - The application automatically retries failed requests (3 attempts with exponential backoff)
   - Check logs for persistent failures that exceed retry attempts
   - Verify API endpoint permissions for your user account
   - Increase `REQUEST_TIMEOUT` for slow network connections

5. **Import/Dependency Errors**
   - Run `pip install -r requirements.txt` to install all dependencies
   - Ensure Python 3.8+ is being used
   - Verify virtual environment is activated if using one
   - Use the installation script: `./install_dependencies.sh`

6. **AI Features Not Working**
   - Check if `OPENAI_API_KEY` is set in `.env` file
   - Verify OpenAI API key is valid and has sufficient quota
   - Ensure AI dependencies are installed (langchain, langchain-openai)
   - Review console output for specific AI error messages

7. **Email Notifications Not Sent**
   - Verify SMTP settings in `.env` file (server, port, credentials)
   - Check `EMAIL_USE_TLS` and `EMAIL_USE_SSL` settings match your SMTP server
   - For Gmail: Use app-specific password, not account password
   - Test SMTP connection manually with `telnet smtp.server.com 587`
   - Check firewall rules allow outbound SMTP connections
   - Review logs for authentication or connection errors

8. **Webex Notifications Not Sent**
   - Verify `WEBEX_BOT_TOKEN` and `WEBEX_SPACE_ID` in `.env` file
   - Ensure bot has been added to the specified Webex space
   - Install Webex SDK: included in requirements.txt
   - Test bot token with Webex API explorer

9. **Teams Notifications Not Sent**
   - Verify `TEAMS_WEBHOOK_URL` in `.env` file is correct
   - Ensure webhook is still active (they can expire if unused)
   - Check Teams channel still exists and webhook hasn't been removed
   - Test webhook with `curl -X POST -H 'Content-Type: application/json' -d '{"text":"test"}' WEBHOOK_URL`
   - Review logs for HTTP errors (400, 404, etc.)

10. **Empty or Incomplete Reports**
    - Check if devices are registered in Catalyst Center
    - Verify user permissions for device and assurance data access
    - Review API endpoint connectivity (some internal APIs may require elevated access)
    - Check log files for specific API call failures

11. **Test Failures**
    - Run `pytest tests/ -v` to see detailed test output
    - Ensure all dependencies are installed
    - Check that test fixtures in `tests/fixtures/` are present

### Logging

The script generates detailed logs in `catalyst_health_monitor.log`:

```bash
# View recent logs
tail -f catalyst_health_monitor.log

# Search for errors
grep ERROR catalyst_health_monitor.log
```

## Security Notes

- **Never commit `.env` file**: The `.env` file is automatically excluded from git tracking
- **Use `.env.example`**: Provides a template without sensitive data
- **Context Manager Support**: The API client implements Python context managers (`with` statement) for automatic resource cleanup and proper session handling
- **Secure Error Logging**: Authentication errors are logged generically to prevent credential exposure in production logs
- **Input Validation**: API parameters are validated to prevent path traversal and injection attacks
- Store credentials securely and rotate them regularly
- Consider using API tokens instead of passwords where possible
- Use HTTPS and verify SSL certificates in production environments
- Limit API user permissions to read-only access where possible
- Review application logs regularly and protect them from unauthorized access

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes following the modular architecture
4. Add or update tests in `tests/` directory
5. Run the test suite: `pytest tests/ -v`
6. Ensure code follows existing patterns and style
7. Update documentation if needed
8. Submit a pull request with a clear description

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/CatC-Health.git
cd CatC-Health

# Install dependencies including testing tools
pip install -r requirements.txt

# Run tests before making changes
pytest tests/ -v

# Make your changes, then run tests again
pytest tests/ --cov=catc_health
```

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the logs (`catalyst_health_monitor.log`) for error details
3. Ensure configuration is valid by checking startup validation messages
4. Run tests to verify installation: `pytest tests/ -v`
5. Open an issue on GitHub with:
   - Relevant log excerpts (redact credentials)
   - Configuration details (redact sensitive values)
   - Steps to reproduce the problem
   - Python version and OS information

## Project Structure

```
CatC-Health/
├── catalyst_health_monitor.py    # Main entry point (483 lines)
├── catc_health/                   # Core package
│   ├── __init__.py               # Package exports
│   ├── client.py                 # API client with retry logic and context managers
│   ├── config.py                 # Configuration and validation
│   ├── ai_analyzer.py            # OpenAI integration with sanitization
│   ├── webex_notifier.py         # Webex Teams messaging
│   ├── report_generator.py       # PDF report generation
│   ├── api_adapter.py            # API field normalization
│   └── utils.py                  # Shared utilities
├── tests/                         # Unit tests
│   ├── conftest.py               # Pytest fixtures
│   ├── test_health_monitor.py    # Test suite
│   └── fixtures/                 # Test data (mock API responses)
├── reports/                       # Generated PDF reports
├── .env.example                   # Configuration template
├── requirements.txt               # Python dependencies (all features)
├── requirements-ai.txt            # AI-specific dependencies only
├── run_health_monitor.sh          # Enhanced execution script
└── install_dependencies.sh        # Dependency installation script
```
