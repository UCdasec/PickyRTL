setup_dependencies() {
    echo "Setting up dependencies..."
    
    sudo apt install build-essential uuid-dev cmake default-jre python3 python3-venv python3-dev python3-pip ninja-build -y

    # Check if venv package is installed
    if dpkg -s python3-venv &>/dev/null; then
        echo 'virtualenv is installed'
    else
        echo 'Installing virtualenv'
        sudo apt install python3-venv -y
    fi

    # Check if virtual environment exists
    if [ -f 'venv/bin/activate' ]; then
        echo "Virtual environment exists"
    else
        echo "Creating virtual environment"
        python3 -m venv venv
    fi

    source venv/bin/activate

    # Check if requirements are installed
    echo 'Checking if packages are installed...'

    if [ -f "requirements.txt" ]; then
        DRYRUN_OUTPUT=$(pip install -r requirements.txt)
        if "$DRYRUN_OUTPUT" | grep -q "Collecting" 2>/dev/null; then
            echo "Installing requirements.txt"
            pip install -r requirements.txt
        else
            echo "Nothing needs to be installed"
        fi
    fi

    echo "Dependencies set up."
}

setup_dependencies

echo "Starting the program..."
echo 
#Run the main Python script
python3 main.py

