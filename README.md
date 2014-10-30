lias
======

Command line tool to create google groups as mail aliases for google apps


## Requires gdata
sudo pip install -U gdata

## Usage

Usage: galias.py [options] COMMAND 
        
Possible COMANDS are:         
    listall - List all aliases         
    list <alias> - list the specified alias         
    add <alias> <destination> - add the <destination> to the <alias>         
    delete <alias> <destination> - delete the <destination> from the <alias>         

Options:
  -h, --help            show this help message and exit
  -u USERNAME, --username=USERNAME
  -p PASSWORD, --password=PASSWORD
  -d DOMAIN, --domain=DOMAIN
  
## Config
Three pieces of informaiton are required, username, password and domain. If they are not given the program will prompt them. For faster use you can pass them on the command line with the above options or copy example_galias.ini to galias.ini and edit it with your information.

## Examples
#### List all aliases
./galias.py listall

#### List specific alias
./galias.py list name@domain.com

#### Add new alias to forward name@domain.com to other@email.com
./galias.py *add* name@domain.com other@gmail.com

#### Delete other@email.com from the name@domain.com alias
./galias.py *delete* name@domain.com other@gmail.com

