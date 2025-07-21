#!/bin/bash

# Cisco Catalyst Center Health Monitor with AI Analysis - Dependency Installation Script

echo "Installing dependencies for Catalyst Center Health Monitor with AI Analysis..."
echo "=============================================================================="

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is required but not installed."
    echo "Please install Python 3.6 or higher first."
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "Python version: $python_version"

# Check if Python version is compatible
if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)'; then
    echo "✓ Python version is compatible"
else
    echo "ERROR: Python 3.6 or higher is required. Current version: $python_version"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create virtual environment"
        exit 1
    fi
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to activate virtual environment"
    exit 1
fi

# Upgrade pip
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install core requirements
echo "Installing core packages..."
python -m pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install core requirements"
    exit 1
fi

echo "✓ Core packages installed successfully"

# Ask user about AI features
echo ""
read -p "Do you want to install AI analysis features (OpenAI + Webex Teams)? [y/N]: " install_ai

if [[ $install_ai =~ ^[Yy]$ ]]; then
    echo "Installing AI and Webex packages..."
    python -m pip install langchain langchain-openai webexteamssdk python-dotenv
    if [ $? -eq 0 ]; then
        echo "✓ AI and Webex packages installed successfully"
        ai_installed=true
    else
        echo "WARNING: Failed to install AI packages. Core functionality will still work."
        ai_installed=false
    fi
else
    echo "Skipping AI packages. You can install them later if needed."
    ai_installed=false
fi

echo ""
echo "Installation completed successfully!"
echo "===================================="
echo ""
echo "The health monitor now supports:"
echo "• PDF report generation (replaces CSV)"
echo "• AI-powered health analysis (if AI packages installed)"
echo "• Webex Teams integration for automated notifications"
echo "• Enhanced error handling and validation"
echo ""

if [ "$ai_installed" = true ]; then
    echo "✓ AI features are available!"
    echo ""
    echo "IMPORTANT: Configure your environment variables in .env file:"
    echo "   # Catalyst Center (Required)"
    echo "   CATALYST_CENTER_URL=https://your-catalyst-center.com"
    echo "   CATALYST_CENTER_USERNAME=your_username"
    echo "   CATALYST_CENTER_PASSWORD=your_password"
    echo ""
    echo "   # AI Analysis (Optional - for AI features)"
    echo "   OPENAI_API_KEY=your_openai_api_key"
    echo ""
    echo "   # Webex Teams (Optional - for notifications)"
    echo "   WEBEX_BOT_TOKEN=your_webex_bot_token"
    echo "   WEBEX_SPACE_ID=your_webex_space_id"
    echo ""
    echo "Run with AI analysis:"
    echo "  ./run_health_monitor.sh --ai-summary"
else
    echo "Basic configuration needed in .env file:"
    echo "   CATALYST_CENTER_URL=https://your-catalyst-center.com"
    echo "   CATALYST_CENTER_USERNAME=your_username"
    echo "   CATALYST_CENTER_PASSWORD=your_password"
    echo ""
    echo "To add AI features later, run:"
    echo "  source venv/bin/activate"
    echo "  pip install langchain langchain-openai webexteamssdk python-dotenv"
fi

echo ""
echo "Usage options:"
echo "  ./run_health_monitor.sh              # Standard health check"
echo "  ./run_health_monitor.sh --ai-summary # With AI analysis (if available)"
echo "  ./run_health_monitor.sh --help       # Show all options"
echo ""
echo "Or activate the environment manually:"
echo "  source venv/bin/activate"
echo "  python catalyst_health_monitor.py [--ai-summary]"
