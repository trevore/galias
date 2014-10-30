#! /usr/bin/python
"""
Copyright 2014 Trevor Ellermann                                                                                                                                         

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import gdata.apps.groups.service

def print_all_members(group_service):
    groups = group_service.RetrieveAllGroups()
    for group in groups:
        print_group(group_service, group)

def list_group(group_service, name):
    group = group_service.RetrieveGroup(name)
    print_group(group_service, group)

def print_members(group_service, group_id):
    gid = ""
    for user in group_service.RetrieveAllMembers(group_id): 
        print gid + "->", user['memberId']
        gid = group_id + " "

def add_to_alias(group_service, alias, address):
    try:
        group = group_service.RetrieveGroup(alias)
    except Exception, e:
        if e.reason == "EntityDoesNotExist":
            print "New Alias " + alias
            name = "Alias " + alias
            group_service.CreateGroup(alias, name, "", "Anyone")
            group = group_service.RetrieveGroup(alias)
        else:
            raise e

    group_service.AddMemberToGroup(address, alias)
    print "Added"
    print "Current status of alias"
    print_group(group_service, group)    
    
def delete_from_alias(group_service, alias, address):
    try:
        group = group_service.RetrieveGroup(alias)
    except Exception, e:
        if e.reason == "EntityDoesNotExist":
            print "Invalid Alias " + alias
        else:
            raise e
        return
    
    members = group_service.RetrieveAllMembers(alias)
    memberlist = []
    for member in members:
        memberlist.append(member["memberId"])
    if address not in memberlist:
        print "*" * 70
        print "* " + address + " is not in " + alias
        print "*" * 70
    else:
        group_service.RemoveMemberFromGroup(address, alias)
        print "Deleted"

    members = group_service.RetrieveAllMembers(alias)
    if not members:
        group_service.DeleteGroup(alias)
        print "Alias empty, removing alias"
    else:
        print "Current status of alias"
        print_group(group_service, group)
    
def print_group(group_service, group): 
    gid = group['groupId'] 
    print('%s' % (gid)), 
    print_members(group_service, gid) 

def main():
    from optparse import OptionParser
    from optparse import OptionGroup
    import os.path
    import ConfigParser
    config_username = ""
    config_password = ""
    config_domain = ""
    if os.path.isfile("galias.ini"):
        Config = ConfigParser.ConfigParser()
        Config.read("galias.ini")
        config_username = Config.get("galias", "username")
        config_password = Config.get("galias", "password")
        config_domain = Config.get("galias", "domain")
    
    usage = "usage: %prog [options] COMMAND \n\
        \nPossible COMANDS are: \
        \n    listall - List all aliases \
        \n    list <alias> - list the specified alias \
        \n    add <alias> <destination> - add the <destination> to the <alias> \
        \n    delete <alias> <destination> - delete the <destination> from the <alias> \
        "
    parser = OptionParser(usage)

    parser.add_option('-u', '--username', default=config_username)
    parser.add_option('-p', '--password', default=config_password)
    parser.add_option('-d', '--domain', default=config_domain)
    group = OptionGroup(parser, "Dangerous Options",
                    "Caution: use these options at your own risk.  "
                    "It is believed that some of them bite.")

    options, args = parser.parse_args()
    command = ""

    if len(args) < 1:
        parser.error("incorrect number of arguments")
    else:
        command = args[0]

    if not options.domain:
        options.domain = raw_input("Google apps domain name: ")
        
    if not options.username:
        username = raw_input("Your administrator username: ")
        options.email = username + "@" + options.domain
    else:
        options.email = options.username + "@" + options.domain

    if not options.password:       
        import getpass 
        password = getpass.getpass('Password: ')
    else: 
        password = options.password or login



    group_service = gdata.apps.groups.service.GroupsService(email=options.email, domain=options.domain, password=password) 
    group_service.ProgrammaticLogin()
    
    # COMMANDS
    if command == "listall":
        print_all_members(group_service)
    elif command == "list":
        print "listing alias", args[1]
        list_group(group_service, args[1])
    elif command == "add":
        print "%s add %s" % (args[1], args[2])
        add_to_alias(group_service, args[1], args[2])
    elif command == "delete":
        print "%s delete %s" % (args[1], args[2])
        delete_from_alias(group_service, args[1], args[2])
    else:
        print "Unknown command"

if __name__ == '__main__': 
    main()
