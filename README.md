galias
======

Command line tool to create google groups as mail aliases for google apps


## Requires the google python API client
`sudo pip install -U google-api-python-client`

## Requires the retrying package
`sudo pip install -U retrying`

## Usage

Usage: `galias.py [options] COMMAND`

Possible COMMANDS are:

* `listall` - List all aliases
* `list <alias>` - list the specified alias
* `list_memberships [addresses]` - list alias memberships for an optional list of addresses
* `add <alias> <destination>` - add the `<destination>` to the `<alias>`
* `delete <alias> <destination>` - delete the `<destination>` from the `<alias>`
* `addfromfile <group> <filen> <owner,manager>` - add the emails listed in `<file>` to `<group>` optionally as `<owner>` or `<manager>`
* `owner <group> <destination>` - set `<destination>` to an owner of `<group>`
* `manager <group> <destination>` - set `<destination>` to a manager of `<group>`
* `member <group> <destination>` - set `<destination>` to member of `<group>`
* `create <group> <type>` - create `<group>` where `<type>` can be [alias, announce, discuss]
* `groupdelete <group>` - delete whole `<group> `WITHOUT CONFIRMATION
* `getsettings <group>` - output the settings for `<group>`
* `updatesettings <group> <type>` - update the settings of `<group>` to `<type>`


Options:

  * `-h, --help`	show this help message and exit
  * `-d DOMAIN`, 	`--domain=DOMAIN`

## Config
The domain to administer is required. If it is not given, the program will prompt for it. For faster use you can pass it on the command line with the above option or copy `example_galias.ini` to `galias.ini` and edit it with your information.

In addition, the script must be registered in the Google Developer console for your domain, and the client_secrets.json file must be present.

## Examples
#### List all aliases
`./galias.py listall`

#### List specific alias
`./galias.py list name@domain.com`

#### Add new alias to forward name@domain.com to other@email.com
`./galias.py add name@domain.com other@gmail.com`

#### Delete other@email.com from the name@domain.com alias
`./galias.py delete name@domain.com other@gmail.com`
