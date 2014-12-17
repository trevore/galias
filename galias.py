#! /usr/bin/env python
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

from collections import defaultdict
from gdata.apps.groups import service
# Used for Error Handling
from gdata.apps.service import AppsForYourDomainException
from xml.etree import ElementTree as etree

def get_group_service(username, password, domain):
    """Construct a Service object and authenticate"""
    group_service = service.GroupsService(email=username, domain=domain, password=password) 
    group_service.ProgrammaticLogin()
    return group_service

def get_all_groups(group_service):
    return group_service.RetrieveAllGroups()

def get_group(group_service, group_name):
    return group_service.RetrieveGroup(group_name)

def get_group_members(group_service, group_email):
    return group_service.RetrieveAllMembers(group_email)

def create_group(group_service, group_id, group_name, description, email_permission):
    return group_service.CreateGroup(group_id, group_name, description, email_permission)

def remove_group(group_service, group_email):
    return group_service.DeleteGroup(group_email)

def add_group_member(group_service, group_email, email_address):
    return group_service.AddMemberToGroup(email_address, group_email)

def remove_group_member(group_service, email_address, group_email):
    return group_service.RemoveMemberFromGroup(email_address, group_email)

def is_group_member(group_service, email_address, group_email):
    return group_service.IsMember(email_address, group_email)

def print_all_members(group_service):
    groups = get_all_groups(group_service)
    for group in groups:
        print_group(group_service, group)

def list_group(group_service, group_email):
    group = get_group(group_service, group_email)
    print_group(group_service, group)

def print_members(group_service, group_email):
    gid = ""
    for user in get_group_members(group_service, group_email):
        print gid + "->", user['memberId']
        gid = group_email + " "

def print_memberships(address, groups):
    # Takes a string and a list of groups
    print address + ":"
    for group in groups: 
        print "  " + group
    print

def retrieve_list_memberships(group_service):
    users = defaultdict(list)
    groups = get_all_groups(group_service)
    for group in groups:
        for user in get_group_members(group_service, group["groupId"]): 
            users[user["memberId"]].append(group["groupId"])
    return users

def print_list_memberships(group_service, users):
    user_memberships = retrieve_list_memberships(group_service)
    if len(users) == 0:
        userlist = sorted(user_memberships)
    else:
        userlist = users

    for user in userlist:
        print_memberships(user, user_memberships[user])

def add_to_alias(group_service, alias, address):
    try:
        group = get_group(group_service, alias)
    except Exception, e:
        if e.reason == "EntityDoesNotExist":
            print "New Alias " + alias
            name = "Alias " + alias
            create_group(group_service, alias, name, "", "Anyone")
            group = get_group(group_service, alias)
        else:
            raise e

    add_group_member(group_service, alias, address)
    print "Added"
    print "Current status of alias"
    print_group(group_service, group)    
    
def delete_from_alias(group_service, alias, address):
    try:
        group = get_group(group_service, alias)
    except Exception, e:
        if e.reason == "EntityDoesNotExist":
            print "Invalid Alias " + alias
        else:
            raise e
        return
    
    if not is_group_member(group_service, address, alias):
        print "*" * 70
        print "* " + address + " is not in " + alias
        print "*" * 70
    else:
        remove_group_member(group_service, address, alias)
        print "Deleted"

    members = get_group_members(group_service, alias)
    if not members:
        remove_group(group_service, alias)
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
        \n    list_memberships [addresses] - list alias memberships for a list of addresses (or all if addresses are missing) \
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

    group_service = get_group_service(username=options.email, domain=options.domain, password=options.password)

    # COMMANDS
    try:
        
        if command == "listall":
            print_all_members(group_service)
        elif command == "list":
            print "listing alias", args[1]
            list_group(group_service, args[1])
        elif command == "list_memberships":
            print "listing alias memberships"
            if len(args) == 1:
                print_list_memberships(group_service, [])
            else:
                print_list_memberships(group_service, args[1:])
        elif command == "add":
            print "%s add %s" % (args[1], args[2])
            add_to_alias(group_service, args[1], args[2])
        elif command == "delete":
            print "%s delete %s" % (args[1], args[2])
            delete_from_alias(group_service, args[1], args[2])
        else:
            print "Unknown command"
    except AppsForYourDomainException as e:
        # Errors are returned in XML.
	    for xml_error in etree.fromstring(e.args[0]['body']):
		    err=xml_error.attrib
		    print 'ERROR: ({}) {}: {}'.format( err['errorCode'],err['reason'],err['invalidInput'])

if __name__ == '__main__': 
    main()
