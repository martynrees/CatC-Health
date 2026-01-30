#!/bin/bash

# Cisco Catalyst Center Health Monitor with AI Analysis - Runner Script

# Set script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Cisco Catalyst Center Health Monitor with AI Analysis"
echo "====================================================="

# Parse command line arguments
SCRIPT_ARGS=()
AI_SUMMARY=false
HELP_REQUESTED=false

for arg in "$@"; do
    case $arg in
        --ai-summary)
            AI_SUMMARY=true
            SCRIPT_ARGS+=("$arg")
            ;;
        --notify-email|--notify-webex|--notify-teams|--no-notifications)
            SCRIPT_ARGS+=("$arg")
            ;;
        --help|-h)
            HELP_REQUESTED=true
            ;;
        *)
            echo "Unknown option: $arg"
            HELP_REQUESTED=true
            ;;
    esac
done

# Display help if requested
if [ "$HELP_REQUESTED" = true ]; then
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --ai-summary         Enable AI-powered health analysis"
    echo "  --notify-email       Send notifications via Email (overrides .env)"
    echo "  --notify-webex       Send notifications via Webex Teams (overrides .env)"
    echo "  --notify-teams       Send notifications via MS Teams (overrides .env)"
    echo "  --no-notifications   Disable all notifications (overrides .env)"
    echo "  --help, -h           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                  # Standard health report only"
    echo "  $0 --ai-summary                     # AI analysis + default notifications"
    echo "  $0 --notify-email                   # Email notification (PDF only)"
    echo "  $0 --ai-summary --notify-email      # AI analysis + email"
    echo "  $0 --notify-webex --notify-teams    # Multi-channel notifications"
    echo "  $0 --ai-summary --no-notifications  # AI analysis, no notifications"
    echo ""
    echo "Notification Configuration:"
    echo "  Configure channels in .env file:"
    echo "    ENABLE_EMAIL_NOTIFICATIONS=true   # Enable email by default"
    echo "    ENABLE_WEBEX_NOTIFICATIONS=true   # Enable Webex by default"
    echo "    ENABLE_TEAMS_NOTIFICATIONS=true   # Enable Teams by default"
    echo "  CLI flags override .env settings for one-time runs"
    echo ""
    exit 0
fi

# Check if virtual environment exists
if [ ! -d "$SCRIPT_DIR/venv" ]; then
    echo "Virtual environment not found. Running installation script..."
    "$SCRIPT_DIR/install_dependencies.sh"
    if [ $? -ne 0 ]; then
        echo "Installation failed. Exiting."
        exit 1
    fi
fi

# Activate virtual environment
echo "Activating virtual environment..."
source "$SCRIPT_DIR/venv/bin/activate"

# Check if .env file exists
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "WARNING: .env file not found."
    echo "Please create a .env file with your Catalyst Center configuration:"
    echo ""
    echo "Required variables:"
    echo "  CATALYST_CENTER_URL=https://your-catalyst-center.example.com"
    echo "  CATALYST_CENTER_USERNAME=your_username"
    echo "  CATALYST_CENTER_PASSWORD=your_password"
    echo ""
    echo "Optional variables:"
    echo "  VERIFY_SSL=false"
    echo "  REQUEST_TIMEOUT=30"
    echo "  DEFAULT_LIMIT=500"
    echo ""
    echo "For AI analysis (--ai-summary):"
    echo "  OPENAI_API_KEY=sk-your-openai-api-key-here"
    echo ""
    echo "For notifications (see .env.example for full details):"
    echo "  ENABLE_EMAIL_NOTIFICATIONS=true"
    echo "  EMAIL_SMTP_SERVER=smtp.gmail.com"
    echo "  EMAIL_FROM=monitor@example.com"
    echo "  EMAIL_TO=admin@example.com"
    echo "  ENABLE_WEBEX_NOTIFICATIONS=true"
    echo "  WEBEX_BOT_TOKEN=your-bot-token"
    echo "  WEBEX_SPACE_ID=your-space-id"
    echo "  ENABLE_TEAMS_NOTIFICATIONS=true"
    echo "  TEAMS_WEBHOOK_URL=https://..."
    echo ""
    echo "You can copy and modify the example .env file if provided."
    echo ""
else
    echo "Configuration file found: .env"

    # Check for AI dependencies if --ai-summary is requested
    if [ "$AI_SUMMARY" = true ]; then
        echo "Checking AI integration requirements..."

        # Check if OpenAI API key is configured
        if ! grep -q "OPENAI_API_KEY=" "$SCRIPT_DIR/.env" || grep -q "OPENAI_API_KEY=sk-your-openai-api-key-here" "$SCRIPT_DIR/.env"; then
            echo "WARNING: OPENAI_API_KEY not configured in .env file"
            echo "AI analysis may not work without a valid OpenAI API key"
        else
            echo "✓ OpenAI API key configured"
        fi

        # Check for AI dependencies
        echo "Checking AI dependencies..."
        if python -c "import langchain, langchain_openai" 2>/dev/null; then
            echo "✓ AI dependencies (langchain, langchain-openai) installed"
        else
            echo "WARNING: AI dependencies missing"
            echo "Run: pip install langchain langchain-openai"
        fi
    fi

    # Check notification channel configurations
    echo "Checking notification channels..."
    
    if grep -q "ENABLE_EMAIL_NOTIFICATIONS=true" "$SCRIPT_DIR/.env" 2>/dev/null; then
        echo "✓ Email notifications enabled"
    fi
    
    if grep -q "ENABLE_WEBEX_NOTIFICATIONS=true" "$SCRIPT_DIR/.env" 2>/dev/null; then
        if grep -q "WEBEX_BOT_TOKEN=" "$SCRIPT_DIR/.env" && ! grep -q "WEBEX_BOT_TOKEN=your-webex-bot-token-here" "$SCRIPT_DIR/.env"; then
            echo "✓ Webex notifications enabled and configured"
        else
            echo "ℹ Webex enabled but not configured"
        fi
    fi
    
    if grep -q "ENABLE_TEAMS_NOTIFICATIONS=true" "$SCRIPT_DIR/.env" 2>/dev/null; then
        echo "✓ MS Teams notifications enabled"
    fi
fi

# Run the health monitor
echo ""
echo "Starting Catalyst Center Health Monitor..."
if [ "$AI_SUMMARY" = true ]; then
    echo "Mode: AI-Enhanced Analysis"
else
    echo "Mode: Standard Health Monitoring"
fi
echo "Time: $(date)"
echo ""

cd "$SCRIPT_DIR"

# Execute the health monitor with all arguments
if [ ${#SCRIPT_ARGS[@]} -gt 0 ]; then
    echo "Running with options: ${SCRIPT_ARGS[*]}"
    python3 catalyst_health_monitor.py "${SCRIPT_ARGS[@]}"
else
    echo "Running standard health check..."
    python3 catalyst_health_monitor.py
fi

# Check exit status
EXIT_CODE=$?
echo ""

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Health monitoring completed successfully!"
    echo ""
    echo "Generated outputs:"
    echo "  📊 PDF Report: Check the reports/ directory"
    echo "  📝 Log File: catalyst_health_monitor.log"

    if [ "$AI_SUMMARY" = true ]; then
        echo "  🤖 AI Analysis: Displayed above"
    fi

    echo ""
    echo "Next steps:"
    echo "  - Review the generated PDF report for detailed analysis"
    echo "  - Check the log file for any warnings or additional information"

    if [ "$AI_SUMMARY" = true ]; then
        echo "  - Review AI summary for actionable insights"
    fi
    
    echo "  - Check notification channels (Email/Webex/Teams) if configured"

else
    echo "❌ Health monitoring failed (Exit code: $EXIT_CODE)"
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Check catalyst_health_monitor.log for detailed error messages"
    echo "  2. Verify .env configuration (especially credentials)"
    echo "  3. Ensure network connectivity to Catalyst Center"
    echo "  4. Check API permissions for your user account"

    if [ "$AI_SUMMARY" = true ]; then
        echo "  5. Verify OpenAI API key is valid and has quota available"
        echo "  6. Check AI dependencies: pip install langchain langchain-openai"
    fi
    
    echo "  For notification issues:"
    echo "    - Email: Verify SMTP settings and credentials"
    echo "    - Webex: Check bot token and space ID"
    echo "    - Teams: Verify webhook URL is valid"

    echo ""
    exit 1
fi

echo "Health monitoring session complete."
