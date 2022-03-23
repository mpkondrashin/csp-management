# CSP Managment

Trend Micro Multi-tenant Deep Security Managment

## Setup environment

Following instructions are for Linux/macOS.

To run please install python3 (https://www.python.org/downloads/) and tkinter.
The latest can be installed using following command (for macOS):
```commandline
brew install python-tk
```
or (for Ubuntu flavored Linux):
```commandline
apt-get install python-tk 
```

Then clone this repository and install required packages:

```commandline
git clone https://github.com/mpkondrashin/csp-management.git
cd csp-managementgit 
python3 -m venv venv
source venv/bin/activate

```commandline
Install Deep Security SDK (https://automation.deepsecurity.trendmicro.com/article/20_0/python/):
```

pip install https://automation.deepsecurity.trendmicro.com/sdk/20_0/v1/dsm-py-sdk.zip

```commandline
Install rest of required packages:
pip install -r requirements.txt
```

## Run Script

Use following command to run script:
```commandline
python gui.py
```

## Build Self-contained Executable

Run following command
```commandline
python build.py
```
This will generate ```extoword``` executable that does not require to have python
to be installed.

Note: This feature was tested only for macOS

## GUI image

![GUI Image](gui.png "GUI image")

## Bugs

This script was not tested under Windows/Linux. Obvious incompatible spot that should be
fixed is following line in config.py:
```python
__folder = os.path.expanduser('~/Library/Application Support/ExToWord')
```
Though Windows icon is added to executable in build.py, this
 is also not tested.