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
from apiclient.errors import HttpError
from apiclient.http import BatchHttpRequest
from apiclient.http import HttpMock
from apiclient import sample_tools
from oauth2client.client import AccessTokenRefreshError
import argparse
import sys
import random
from retrying import retry
import os.path
import pprint


def retry_if_http_error(exception):
    """Return True if we should retry  False otherwise"""
    return isinstance(exception, HttpError)

# Implement backoff in case of API rate errors
@retry(wait_exponential_multiplier=1000,
       wait_exponential_max=10000,
       retry_on_exception=retry_if_http_error,
       wrap_exception=False)
def execute_with_backoff(request):
    response = request.execute()
    return response


def get_all_groups(group_service, domain=None):
    all_groups = []
    request = group_service.list(domain=domain)
    while (request is not None):
        response = execute_with_backoff(request)
        all_groups.extend(response['groups'])
        request = group_service.list_next(request, response)
    return all_groups

def get_group(group_service, group_name):
    request = group_service.get(groupKey=group_name)
    response = execute_with_backoff(request)
    return response

def get_group_members(member_service, group_email):
    members = []
    request = member_service.list(groupKey=group_email)
    while (request is not None):
        response = execute_with_backoff(request)
        try:
            members.extend(response['members'])
        except KeyError:
            return None
        request = member_service.list_next(request, response)
    return members

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


def print_all_members(service,domain):
    groups = get_all_groups(service.groups(), domain)
    for group in groups:
        print_group(service.members(), group)

def list_group(service, group_email):
    group = get_group(service.groups(), group_email)
    print_group(service.members(), group)

def print_members(service, group_email):
    gid = ""
    members = get_group_members(service, group_email)
    if members:
        for user in members:
            try:
                print gid + "->", user['email']
                gid = group_email + " "
            except KeyError:
                continue
    else:
        print gid + "-> Empty"

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


def print_group(member_service, group):
    gid = group['email']
    print('%s' % (gid)),
    print_members(member_service, gid)

def main(argv):
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
    # addHelp=False here because it's added downstream in the sample_init
    argparser = argparse.ArgumentParser(add_help=False)
    argparser.add_argument(
        'command',
        choices=['listall', 'list'],
        help='Action to be taken')
    argparser.add_argument('args', nargs=argparse.REMAINDER)

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

    # Authenticate and construct service
    scope = ("https://www.googleapis.com/auth/admin.directory.group"
             " "
             "https://www.googleapis.com/auth/admin.directory.group.member")
    service, flags = sample_tools.init(
        argv, 'admin', 'directory_v1', __doc__, __file__, parents=[argparser],
        scope=scope
        )

    # COMMANDS

    if flags.command == "listall":
        print_all_members(service, config_domain)
    elif flags.command == "list":
        if not flags.args:
            argparser.print_help()
            exit(1)
        print "listing alias", flags.args[0]
        list_group(service, flags.args[0])
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


if __name__ == '__main__':
    main(sys.argv)
