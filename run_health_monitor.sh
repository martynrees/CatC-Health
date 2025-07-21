#!/bin/bash

# Cisco Catalyst Center Health Monitor with AI Analysis - Runner Script

# Set script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Cisco Catalyst Center Health Monitor with AI Analysis"
echo "====================================================="

# Parse command line arguments
AI_SUMMARY_FLAG=""
HELP_REQUESTED=false

for arg in "$@"; do
    case $arg in
        --ai-summary)
            AI_SUMMARY_FLAG="--ai-summary"
            echo "AI-powered analysis enabled"
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
    echo "  --ai-summary    Enable AI-powered analysis and Webex messaging"
    echo "  --help, -h      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Generate standard health report"
    echo "  $0 --ai-summary       # Generate health report with AI analysis"
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
    if [ "$AI_SUMMARY_FLAG" = "--ai-summary" ]; then
        echo "For AI features (--ai-summary), also add:"
        echo "  OPENAI_API_KEY=sk-your-openai-api-key-here"
        echo ""
        echo "For Webex Teams integration, also add:"
        echo "  WEBEX_BOT_TOKEN=your-webex-bot-token-here"
        echo "  WEBEX_SPACE_ID=your-webex-space-id-here"
        echo ""
    fi
    echo "You can copy and modify the example .env file if provided."
    echo ""
else
    echo "Configuration file found: .env"

    # Check for AI dependencies if --ai-summary is requested
    if [ "$AI_SUMMARY_FLAG" = "--ai-summary" ]; then
        echo "Checking AI integration requirements..."

        # Check if OpenAI API key is configured
        if ! grep -q "OPENAI_API_KEY=" "$SCRIPT_DIR/.env" || grep -q "OPENAI_API_KEY=sk-your-openai-api-key-here" "$SCRIPT_DIR/.env"; then
            echo "WARNING: OPENAI_API_KEY not configured in .env file"
            echo "AI analysis may not work without a valid OpenAI API key"
        else
            echo "✓ OpenAI API key configured"
        fi

        # Check if Webex configuration exists (optional)
        if grep -q "WEBEX_BOT_TOKEN=" "$SCRIPT_DIR/.env" && ! grep -q "WEBEX_BOT_TOKEN=your-webex-bot-token-here" "$SCRIPT_DIR/.env"; then
            echo "✓ Webex Teams integration configured"
        else
            echo "ℹ Webex Teams integration not configured (optional)"
        fi

        # Check for AI dependencies
        echo "Checking AI dependencies..."
        if python -c "import langchain, langchain_openai" 2>/dev/null; then
            echo "✓ AI dependencies (langchain, langchain-openai) installed"
        else
            echo "WARNING: AI dependencies missing"
            echo "Run: pip install langchain langchain-openai"
        fi

        # Check for Webex dependencies
        if python -c "import webexteamssdk" 2>/dev/null; then
            echo "✓ Webex Teams SDK installed"
        else
            echo "ℹ Webex Teams SDK not installed (optional)"
            echo "For Webex integration, run: pip install webexteamssdk"
        fi
    fi
fi

# Run the health monitor
echo ""
echo "Starting Catalyst Center Health Monitor..."
if [ "$AI_SUMMARY_FLAG" = "--ai-summary" ]; then
    echo "Mode: AI-Enhanced Analysis with Webex Integration"
else
    echo "Mode: Standard Health Monitoring"
fi
echo "Time: $(date)"
echo ""

cd "$SCRIPT_DIR"

# Execute the health monitor with appropriate arguments
if [ "$AI_SUMMARY_FLAG" = "--ai-summary" ]; then
    echo "Running with AI analysis..."
    python3 catalyst_health_monitor.py --ai-summary
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

    if [ "$AI_SUMMARY_FLAG" = "--ai-summary" ]; then
        echo "  🤖 AI Analysis: Displayed above"
        echo "  📧 Webex Message: Sent to configured space (if configured)"
    fi

    echo ""
    echo "Next steps:"
    echo "  - Review the generated PDF report for detailed analysis"
    echo "  - Check the log file for any warnings or additional information"

    if [ "$AI_SUMMARY_FLAG" = "--ai-summary" ]; then
        echo "  - Review AI summary for actionable insights"
        echo "  - Check Webex space for the automated message and report"
    fi

else
    echo "❌ Health monitoring failed (Exit code: $EXIT_CODE)"
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Check catalyst_health_monitor.log for detailed error messages"
    echo "  2. Verify .env configuration (especially credentials)"
    echo "  3. Ensure network connectivity to Catalyst Center"
    echo "  4. Check API permissions for your user account"

    if [ "$AI_SUMMARY_FLAG" = "--ai-summary" ]; then
        echo "  5. Verify OpenAI API key is valid and has quota available"
        echo "  6. Check AI dependencies: pip install langchain langchain-openai"
        echo "  7. For Webex issues: verify bot token and space ID"
    fi

    echo ""
    exit 1
fi

echo "Health monitoring session complete."
