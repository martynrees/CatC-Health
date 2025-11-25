# Cisco Catalyst Center Health Monitor with AI Analysis

A modular Python application that connects to Cisco Catalyst Center and generates daily health reports for network devices and assurance issues in **PDF format**, with optional **AI-powered analysis** and **Webex Teams integration**.

## Architecture

The application uses a modular package structure for improved maintainability and testability:

- **`catc_health/`** - Core package with specialized modules:
  - `client.py` - API client with automatic retry logic
  - `config.py` - Configuration management and validation
  - `ai_analyzer.py` - OpenAI GPT-4o-mini integration
  - `webex_notifier.py` - Webex Teams messaging
  - `report_generator.py` - PDF report generation
  - `api_adapter.py` - API field normalization
  - `utils.py` - Shared utilities
- **`catalyst_health_monitor.py`** - Main entry point (432 lines)
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
- 📧 **Webex Teams Integration**: Automated messaging and report distribution
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
- **Optional**: Webex Teams bot token and space ID for automated messaging

## Installation

1. **Clone or download the repository:**
   ```bash
   git clone <repository-url>
   cd CatC-Health
   ```

2. **Install dependencies:**
   ```bash
   # Install all dependencies (recommended)
   pip install -r requirements.txt

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

# Webex Teams Integration
WEBEX_BOT_TOKEN=your-webex-bot-token-here
WEBEX_SPACE_ID=your-webex-space-id-here

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

# Run standard monitoring
./run_health_monitor.sh

# Run AI-enhanced monitoring with Webex integration
./run_health_monitor.sh --ai-summary
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
The AI and Webex integrations are optional and gracefully degrade if:
- API keys are missing or invalid
- Dependencies are not installed
- API quota is exceeded
- Services are unavailable

Specific error messages guide users to resolve configuration issues.

## Dependencies

All dependencies are managed in `requirements.txt`:

### Core Dependencies
- `requests>=2.25.0` - HTTP client for API calls
- `urllib3>=1.26.0` - HTTP library with SSL support
- `python-dotenv>=0.19.0` - Environment variable management
- `reportlab>=3.6.0` - PDF generation library
- `tenacity>=8.2.0` - Retry logic with exponential backoff

### AI and Integration Dependencies (Optional)
- `langchain>=0.1.0` - AI framework for structured LLM interactions
- `langchain-openai>=0.1.0` - OpenAI GPT-4o-mini integration
- `webexteamssdk>=1.6.0` - Webex Teams API integration

### Testing Dependencies
- `pytest>=7.4.0` - Unit testing framework
- `pytest-cov>=4.1.0` - Code coverage reporting

**Note**: The application gracefully handles missing optional dependencies and will continue to function without AI/Webex features if these packages are not installed.

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

7. **Webex Messages Not Sent**
   - Verify `WEBEX_BOT_TOKEN` and `WEBEX_SPACE_ID` in `.env` file
   - Ensure bot has access to the specified Webex space
   - Install Webex SDK: included in requirements.txt
   - Check bot permissions in Webex Teams

8. **Empty or Incomplete Reports**
   - Check if devices are registered in Catalyst Center
   - Verify user permissions for device and assurance data access
   - Review API endpoint connectivity (some internal APIs may require elevated access)
   - Check log files for specific API call failures

9. **Test Failures**
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
├── catalyst_health_monitor.py    # Main entry point (432 lines)
├── catc_health/                   # Core package
│   ├── __init__.py               # Package exports
│   ├── client.py                 # API client with retry logic
│   ├── config.py                 # Configuration and validation
│   ├── ai_analyzer.py            # OpenAI integration
│   ├── webex_notifier.py         # Webex Teams messaging
│   ├── report_generator.py       # PDF report generation
│   ├── api_adapter.py            # API field normalization
│   └── utils.py                  # Shared utilities
├── tests/                         # Unit tests
│   ├── conftest.py               # Pytest fixtures
│   ├── test_health_monitor.py    # Test suite
│   └── fixtures/                 # Test data
├── reports/                       # Generated PDF reports
├── .env.example                   # Configuration template
├── requirements.txt               # Python dependencies
├── run_health_monitor.sh          # Enhanced execution script
└── install_dependencies.sh        # Dependency installation script
```
