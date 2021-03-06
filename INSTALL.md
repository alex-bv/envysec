# secEnvyronment installation guide.

## Content:
* Requirements;
* Installation;
* Explanation;
* Reference;


## Requirements:
1. Applications:
 - clamav >= 0.101.2
 - python3 >=3.6
 - python3-pip >= 19.2.1
2. Python 3d-party modules:
 - requests>=2.22.0
3. Python default modules:
 - datetime
 - hashlib
 - json
 - logging
 - os
 - pathlib
 - queue
 - subprocess
 - threading
 - time
 - sqlite3

Metadefender API key.
To get Metadefender API key, one need to visit a Metadefender website and get a free key (limited usage) or buy extended API access key.

Notes:
* Other versions may possibly work, but were not tested. Instruction may not work using software or modules different from listed.
* In order to make secEnvyronment usage more secure, recommend to use latest version of ClamAV and requests module.


## Installation:
In this section listed a quick installation guide for Linux (Debian, Debian-based) OS and Windows OS.
Other Linux OS' havent been tested but probably would work.

### Linux (Debian):

1. In terminal:
```
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install clamav python3 python3-pip    
sudo python3 -m pip install -r requirements.txt
python3 envy_sec.py
```

Minimal python3 (python3-minimal) package may not work properly, as it may not contain all necessary modules.
To avoid permissions causes, you may use: ```python3 -m pip install -r requirements.txt --user``` to install requests package into current user's workspace (may lead to bugs, see notes below).


### Windows:

1. Download and install [ClamAV from official site](https://www.clamav.net/).
2. Download and install [python3 from official site](https://www.python.org/) or from Windows 10 Microsoft Store.
- Check if python also added to PATH (check box while installation or add it manually).
- Check if pip installed (check box while installation or install it manually).
3. In command line (cmd or PowerShell): ```python -m pip install -r requirements.txt```
- Make sure use Python 3, not 2. To check version use: ```python -V```;
- To avoid permissions issues, you may use: ```python -m pip install -r requirements.txt --user``` to install required packages into current user's workspace (see ```requirements.txt``` to check all required 3-d party packages and versions).
4. In command line (cmd or PowerShell): ```python envy_sec.py```


***Notes:***
* Using ```--user``` keyword may lead to missing of ```requests``` module to other users, not recommended in systems, used by 2 or more users.
* Recommend to use latest version of ```requests``` module (in order to stay secure), but stable work is not guaranteed.
* In some situations, app will request privileges to run update or scan; this may cause problems with ```--user``` flag (running sudo change current user to 'root').


## Explanation:

In this section, listed quick explanation of why modules are actually have been used.
secEnvyronment uses Python to perform automatic scanning using ClamAV CLI interface.
Following packages and modules used:

1. Python:
    used to provide "Human-Machine" interface in order to automatize scanning tasks.

    - requests module:
        used to send and receive data about files to Metadefender using Rest API.
        See metadefender.py for more technical explanation.

    - hashlib module:
        used to calculate file's hash in order to send it to Metadefender.
        It does not send anything by itself, module used only to calculate.
        See metadefender.py for more technical explanation.

    - datetime, time modules:
        used to print date and time in log files or console.

    - logging module:
        used to create standard log file.
        In secEnvyronment log file is named 'secEnvyronment.log'.

    - os module:
        used to detect user OS and check if files existence/permissions.

    - queue, subprocess, threading modules:
        used to call ClamAV scan task and print it to console;
        See metadefender.py and clamav.py for more technical details.

    - pathlib:
        used to format and verify paths for specific platforms (Windows, Linux);

    - sqlite3:
        used to control used databases (exclusion database and etc.);

2. python3-pip (or pip):
    used to download, install and upgrade python's modules (including 3d-party).

3. ClamAV:
    main ClamAV package, used to perform 'first-layer' scan;
    Any detection will further sended to Metadefender and checked by 30+ engines (in order
    to avoid false-positive and validate threat).


## Reference:

- [ClamAV source code](https://github.com/Cisco-Talos/clamav-devel)

- [Python Software Foundation - Official Site](https://www.python.org/)
- [Installing Python modules (pip explanation)](https://docs.python.org/3/installing/index.html)

- [Python documentation - datetime](https://docs.python.org/3/library/datetime.html)
- [Python documentation - hashlib](https://docs.python.org/3/library/hashlib.html)
- [Python documentation - logging](https://docs.python.org/3/library/logging.html)
- [Python documentation - os](https://docs.python.org/3/library/os.html)
- [Python documentation - pathlib](https://docs.python.org/3/library/pathlib.html)
- [Python documentation - queue](https://docs.python.org/3/library/queue.html)
- [Python documentation - subprocess](https://docs.python.org/3/library/subprocess.html)
- [Python documentation - threading](https://docs.python.org/3/library/threading.html)
- [Python documentation - time](https://docs.python.org/3/library/time.html)
- [Python documentation - sqlite3](https://docs.python.org/3/library/sqlite3.html)

- [Read the Docs - requests](https://readthedocs.org/projects/requests/)
- [GitHub - requests](https://github.com/psf/requests)
