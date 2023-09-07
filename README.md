# ReleaseTheHounds
Tool to upload large datasets and interact with BloodHound CE API. I have encountered issues uploading large files to the API. This project will take a `.zip` file or a directory of JSON data files from `SharpHound.exe` data collector, split the file into workable chunks, and submit them to the BHCE API for ingestion.

The `api.py` code is built from the [sample API client provided by @SpecterOps](https://support.bloodhoundenterprise.io/hc/en-us/articles/11311053342619-Working-with-the-BloodHound-API). You may find this project helpful to reference or expand upon when interacting with the API.

```
                  __________       .__                                  
                  \______   \ ____ |  |   ____ _____    ______ ____   
                   |       __/ __ \|  | _/ __ \\__  \  /  ____/ __ \  
                   |    |   \  ___/|  |_\  ___/ / __ \_\___ \\  ___/  
                   |____|_  /\___  |____/\___  (____  /____  >\___  > 
                          \/     \/          \/     \/     \/     \/  
              __  .__               ___ ___                         .___      
            _/  |_|  |__   ____    /   |   \  ____  __ __  ____   __| _/______
            \   __|  |  \_/ __ \  /    ~    \/  _ \|  |  \/    \ / __ |/  ___/
             |  | |   Y  \  ___/  \    Y    (  <_> |  |  |   |  / /_/ |\___ \ 
             |__| |___|  /\___  >  \___|_  / \____/|____/|___|  \____ /____  >
                       \/     \/         \/                   \/     \/    \/
```

## Installation
This project should be easy to install & set up. You may need to install `requests` if you don't already have it. 

```bash
pip3 install requests
git clone https://githu.com/deletehead/ReleaseTheHounds.git
cd ReleaseTheHounds
python3 ReleaseTheHounds -h
```

## Usage
Provide the file location (`-l`) of eitha a SharpHound `.zip` file (in which case it will be extracted) or a directory with already-extracted JSON files.

```bash
## Just specify the zip
ls *.zip
python3 release_the_hounds.py -l bh.zip

## Specify a folder of JSON files
ls bloodhounddata/
python3 release_the_hounds.py -l ./bloodhounddata/
```

#### Configuring Authentication
You have two options to authenticate to the API:
  1. Configure your domain & token info in `constants.py`
  2. Specify in the command line

![Release the Hounds](https://media.giphy.com/media/fveEm9uqUas7igLGTU/giphy.gif)
