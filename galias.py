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
from optparse import OptionParser
from optparse import OptionGroup
import argparse
import copy
import simplejson
import os.path
import ConfigParser
import time
from apiclient.errors import HttpError
from apiclient.discovery import build
import httplib2
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client import tools
from oauth2client.tools import run_flow
from oauth2client.client import AccessTokenRefreshError
import sys
import random
from retrying import retry
import pprint

# CLIENT_SECRETS, name of a file containing the OAuth 2.0 information for this
# application, including client_id and client_secret, which are found
# on the API Access tab on the Google APIs
# Console <http://code.google.com/apis/console>
CLIENT_SECRETS = 'client_secrets.json'

# Helpful message to display in the browser if the CLIENT_SECRETS file
# is missing.
MISSING_CLIENT_SECRETS_MESSAGE = """
WARNING: Please configure OAuth 2.0

To make this sample run you will need to populate the client_secrets.json file
found at:

   %s

with information from the APIs Console <https://code.google.com/apis/console>.

""" % os.path.join(os.path.dirname(__file__), CLIENT_SECRETS)

# List of valid group types
VALID_GROUP_TYPES = ["alias", "announce", "discuss"]

# API Reference for settings at
# https://developers.google.com/admin-sdk/groups-settings/v1/reference/groups

# Global settings for all lists
globalSettings = {}
globalSettings['sendMessageDenyNotification'] = 'false'
globalSettings['description'] = ''
globalSettings['whoCanViewGroup'] = 'ALL_MEMBERS_CAN_VIEW'
globalSettings['allowExternalMembers'] = 'true'
globalSettings['whoCanInvite'] = 'ALL_MANAGERS_CAN_INVITE'
globalSettings['whoCanContactOwner'] = 'ALL_MEMBERS_CAN_CONTACT'
globalSettings['whoCanViewMembership'] = 'ALL_MANAGERS_CAN_VIEW'

# Fuck it, I've tried everything and I can't find a valid value for english --Trevor
# globalSettings['primaryLanguage'] = 'en-US'

# Alias specific settings
aliasSettings = copy.copy(globalSettings)
aliasSettings['whoCanPostMessage'] = 'ANYONE_CAN_POST'
aliasSettings['messageModerationLevel'] = 'MODERATE_NONE'
aliasSettings['maxMessageBytes'] = '10240000'
aliasSettings['spamModerationLevel'] = 'ALLOW'
aliasSettings['showInGroupDirectory'] = 'false'
aliasSettings['isArchived'] = 'false'
aliasSettings['whoCanJoin'] = 'INVITED_CAN_JOIN'
aliasSettings['membersCanPostAsTheGroup'] = 'true'

# Discuss specific settings
discussSettings = copy.copy(globalSettings)
discussSettings['whoCanPostMessage'] = 'ALL_MEMBERS_CAN_POST'
discussSettings['messageModerationLevel'] = 'MODERATE_NONE'
discussSettings['spamModerationLevel'] = 'MODERATE'
discussSettings['showInGroupDirectory'] = 'true'
discussSettings['isArchived'] = 'true'
discussSettings['whoCanJoin'] = 'INVITED_CAN_JOIN'
discussSettings['membersCanPostAsTheGroup'] = 'false'

# Announce specific settings
announceSettings = copy.copy(globalSettings)
announceSettings['whoCanPostMessage'] = 'ALL_MANAGERS_CAN_POST'
announceSettings['messageModerationLevel'] = 'MODERATE_ALL_MESSAGES'
announceSettings['spamModerationLevel'] = 'MODERATE'
announceSettings['showInGroupDirectory'] = 'true'
announceSettings['isArchived'] = 'true'
announceSettings['whoCanJoin'] = 'CAN_REQUEST_TO_JOIN'
announceSettings['membersCanPostAsTheGroup'] = 'false'

def retry_if_http_error(exception):
    """Return True if we should retry  False otherwise"""
    return isinstance(exception, HttpError)

# Implement backoff in case of API rate errors
# @retry(wait_exponential_multiplier=1000,
#        wait_exponential_max=10000,
#        retry_on_exception=retry_if_http_error,
#        wrap_exception=False)
def execute_with_backoff(request, raiseexceptions = False, existCheck = False):
    try:
        response = request.execute()
    except HttpError, e:
        if raiseexceptions:
            raise e
        elif e._get_reason() == "Member already exists.":
            if not existCheck:
                print "Member already exists, skipping."
            return
        elif "Resource Not Found:" in e._get_reason():
            print "Invalid email, skipping."
            return
        elif "Invalid Input: memberKey" in e._get_reason():
            print "Invalid memeber, skipping."
            return "Invalid memberKey"
        else:
            print 'Error: %d (%s) - %s' % (e.resp.status, e.resp.reason, e._get_reason())
            sys.exit()
    return response


def query_group_type():
    valid = {"l": "alias", "L": "alias", "Alias": "alias", "alias": "alias",
             "d": "discuss", "D": "discuss", "Discuss": "discuss", "discuss": "discuss",
             "n": "announce", "N": "announce", "Announce": "announce", "announce": "announce"}

    prompt = " [L/D/N] "

    while True:
        sys.stdout.write("Is this group aLias, aNnounce or Disccusion" + prompt)
        choice = raw_input().lower()
        if choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'alias' or 'announce' or 'discuss' "
                             "(or 'L' or 'N' or 'D').\n")


def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def get_all_groups(admin_service, domain=None, user=None):
    group_service = admin_service.groups()
    all_groups = []
    request = group_service.list(domain=domain, userKey=user)
    while (request is not None):
        response = execute_with_backoff(request)
        all_groups.extend(response['groups'])
        request = group_service.list_next(request, response)
    return all_groups


def get_group(admin_service, group_name):
    group_service = admin_service.groups()
    request = group_service.get(groupKey=group_name)
    response = execute_with_backoff(request)
    return response


def get_group_settings(group_settings_service, group_name):
    group_settings = group_settings_service.groups()
    request = group_settings.get(groupUniqueId="trevortest@burningman.org")
    response = execute_with_backoff(request)
    return response

def update_group_settings(admin_service, group_settings_service, group_id, group_type):
    print "Updating group %s to type %s" % (group_id, group_type)
    if group_type == "alias":
        settings = aliasSettings
    elif group_type == "announce":
        settings = announceSettings
    elif group_type == "discuss":
        settings = discussSettings
    else:
        print "Invalid group type: \"" + group_type + "\""
        sys.exit()

    settings_service = group_settings_service.groups()
    request = settings_service.patch(groupUniqueId=group_id, body=settings)
    settings = execute_with_backoff(request)


def get_group_members(admin_service, group_email):
    member_service = admin_service.members()
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


def create_group(admin_service, group_settings_service, group_id, group_type=None):
    if group_type is None:
        group_type = query_group_type()
    elif group_type is not None and group_type not in VALID_GROUP_TYPES:
        print "Invalid group type: " + group_type
        group_type = query_group_type()

    if group_type == "alias":
        settings = aliasSettings
    elif group_type == "announce":
        settings = announceSettings
    elif group_type == "discuss":
        settings = discussSettings
    else:
        print "Invalid group type: \"" + group_type + "\""
        sys.exit()

    group_service = admin_service.groups()
    body = {}
    body['email'] = group_id
    body['name'] = group_id.split("@", 1)[0].title() + " " + group_type.title()

    request = group_service.insert(body=body)
    group = execute_with_backoff(request)   
    time.sleep(1)
    settings_service = group_settings_service.groups()
    request = settings_service.patch(groupUniqueId=group_id, body=settings)
    settings = execute_with_backoff(request)
    return group


def remove_group(admin_service, groupUniqueId):
    group_service = admin_service.groups()
    request = group_service.delete(groupKey=groupUniqueId)
    response = execute_with_backoff(request)
    return response


def add_group_member(admin_service, group_email, email_address, role="MEMBER", existCheck=False):
    member_service = admin_service.members()
    request = member_service.insert(groupKey=group_email, body={'email': email_address, 'role': role})
    response = execute_with_backoff(request, existCheck)
    return response

def replace_group_member_expanding_groups(admin_service, group_email, email_address, role="MEMBER", existCheck=False):
    result = add_group_member(admin_service, group_email, email_address, role, existCheck)
    if "Invalid memberKey" in result:
        isGroup = group_exists(admin_service, email_address)
        if isGroup:
            members = get_group_members(admin_service, email_address)
            for member in members:
                member_email = member['email']
                delete_from_group(admin_service, group_email, member_email, nopurge=True, quiet=True)
                result = replace_group_member_expanding_groups(admin_service, group_email, member_email, role, existCheck)
    return result


def remove_group_member(admin_service, email_address, group_email):
    member_service = admin_service.members()
    request = member_service.delete(groupKey=group_email,
                                    memberKey=email_address)
    response = execute_with_backoff(request)
    return response


def is_group_member(admin_service, email_address, group_email):
    try:
        member_service = admin_service.members()
        request = member_service.get(groupKey=group_email,
                                     memberKey=email_address)
        response = execute_with_backoff(request)
        return True
    except HttpError, e:
        try:
            # Load Json body.
            error = simplejson.loads(e.content).get('error')
        except ValueError:
            # Could not load Json body.
            print 'HTTP Status code: %d' % e.resp.status
            print 'HTTP Reason: %s' % e.resp.reason
            raise(e)
        reason = error['errors'][0]['reason']
        if error['code'] == 404 and reason == 'notFound':
            return False
        else:
            print 'Error code: %d' % error.get('code')
            print 'Error message: %s' % error.get('message')
            raise e
    return True


def print_all_members(admin_service, domain):
    groups = get_all_groups(admin_service, domain)
    for group in groups:
        print_group(admin_service, group)


def list_group(admin_service, group_email):
    group = get_group(admin_service, group_email)
    print_group(admin_service, group)


def group_exists(admin_service, group_email):
    group = get_group(admin_service, group_email)
    if group is None:
        return False
    else:
        return True


def count_group(admin_service, group_email):
    group = get_group(admin_service, group_email)
    return group['directMembersCount']


def print_members(admin_service, group_email):
    gid = ""
    members = get_group_members(admin_service, group_email)
    if members:
        for user in members:
            try:
                if user['role'] != "MEMBER":
                    role = " (" + user['role'] + ")"
                else:
                    role = ""
                print gid + "->", user['email'] + role
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


def retrieve_list_memberships(admin_service, domain, userlist):
    users = defaultdict(list)
    if len(userlist) == 0:
        groups = get_all_groups(admin_service, domain)
        for group in groups:
            members = get_group_members(admin_service, group['email'])
            if members is not None:
                for user in members:
                    try:
                        users[user["email"]].append(group['email'])
                    except KeyError:
                        continue
    else:
        for user in userlist:
            groups = get_all_groups(admin_service, domain, user)
            for group in groups:
                users[user].append(group['email'])
    return users


def print_list_memberships(admin_service, domain, users):
    user_memberships = retrieve_list_memberships(admin_service, domain, users)
    if len(users) == 0:
        userlist = sorted(user_memberships)
    else:
        userlist = users

    for user in userlist:
        print_memberships(user, user_memberships[user])


def add_to_group_from_file(admin_service, group_settings_service, groupid, filename, role="MEMBER"):
    existCheck = False
    if "MEMBER" not in role:
        existCheck = True

    print "Adding group members from " + filename
    with open(filename) as inputfile:
        emails = inputfile.readlines()
        for email in emails:
            if not email.isspace():
                print "Adding %s" % email
                add_to_group(admin_service, group_settings_service, groupid, email.strip(), role, status=False, existCheck=existCheck)
    print "Current status of group"
    group_service = admin_service.groups()
    request = group_service.get(groupKey=groupid)
    group = execute_with_backoff(request, True)    
    print_group(admin_service, group)


def add_to_group(admin_service, group_settings_service, groupid, address, role="MEMBER", status=True, existCheck=False):
    exists = False
    try:
        group_service = admin_service.groups()
        request = group_service.get(groupKey=groupid)
        group = execute_with_backoff(request, True)
    except HttpError, e:
        try:
            # Load Json body.
            error = simplejson.loads(e.content).get('error')
        except ValueError:
            # Could not load Json body.
            print 'HTTP Status code: %d' % e.resp.status
            print 'HTTP Reason: %s' % e.resp.reason
            raise(e)
        reason = error['errors'][0]['reason']
        if error['code'] == 404 and reason == 'notFound':
            print "New group " + groupid
            group = create_group(admin_service, group_settings_service, groupid)
        else:
            print 'Error code: %d' % error.get('code')
            print 'Error message: %s' % error.get('message')
            raise e
    try:
        if "MEMBER" not in role:
            result = replace_group_member_expanding_groups(admin_service, groupid, address, role, existCheck)
        else:
            result = add_group_member(admin_service, groupid, address, role, existCheck)
        if status:
            print "Added"
    except HttpError, e:
        try:
            # Load Json body.
            error = simplejson.loads(e.content).get('error')
        except ValueError:
            # Could not load Json body.
            print 'HTTP Status code: %d' % e.resp.status
            print 'HTTP Reason: %s' % e.resp.reason
            raise(e)
        reason = error['errors'][0]['reason']
        if error['code'] == 409 and reason == 'duplicate':
            if existCheck:
                print "%s set %s to %s" % (groupid, address, role)
                delete_from_group(admin_service, groupid, address, nopurge=True, quiet=True)
                add_to_group(admin_service, group_settings_service, groupid, address, role=role, status=status)
            else:
                print '%s is already a member of %s' % (address, groupid)
        else:
            print 'Error code: %d' % error.get('code')
            print 'Error message: %s' % error.get('message')
            print 'Error reason: %s' % error['errors'][0]['reason']
            raise e
    if status:
        print "Current status of group"
        print_group(admin_service, group)


def delete_from_group(admin_service, groupid, address, nopurge=False, quiet=False):
    try:
        group_service = admin_service.groups()
        request = group_service.get(groupKey=groupid)
        group = execute_with_backoff(request)
    except HttpError, e:
        try:
            # Load Json body.
            error = simplejson.loads(e.content).get('error')
        except ValueError:
            # Could not load Json body.
            print 'HTTP Status code: %d' % e.resp.status
            print 'HTTP Reason: %s' % e.resp.reason
            raise(e)
        reason = error['errors'][0]['reason']
        if error['code'] == 404 and reason == 'notFound':
            print 'Error: group %s does not exist' % groupid
            exit(1)
        else:
            print 'Error code: %d' % error.get('code')
            print 'Error message: %s' % error.get('message')
            raise e

    if not is_group_member(admin_service, address, groupid):
        print "*" * 70
        print "* " + address + " is not in " + groupid
        print "*" * 70
    else:
        response = remove_group_member(admin_service, address, groupid)
        if not response and not quiet:
            print "Deleted"
        elif not quiet:
            print "Error: There was a problem removing the group member"

    members = get_group_members(admin_service, groupid)
    if not members and nopurge == False:
        answer = query_yes_no("Group empty, delete it?")
        if answer:
            if not remove_group(admin_service, group['id']):
                print "group empty, removing group"
            else:
                print "Error removing group"
        else:
            print "Leaving empty group"
    elif nopurge == False:
        print "Current status of group"
        print_group(admin_service, group)


def print_group(admin_service, group):
    gid = group['email']
    print('%s' % (gid)),
    print_members(admin_service, gid)


def print_group_settings(group_settings_service, gid):
    print('%s \n' % (gid)),
    settings = get_group_settings(group_settings_service, gid)
    if settings:
        for setting in settings:
            try:
                print setting + ": " + str(settings[setting])
            except KeyError:
                continue
    else:
        print gid + "-> Empty"


def main(argv):
    config_domain = ""
    if os.path.isfile("galias.ini"):
        Config = ConfigParser.ConfigParser()
        Config.read("galias.ini")
        config_domain = Config.get("galias", "domain")

    usage = "usage: %prog [options] COMMAND \n\
        \nPossible COMANDS are: \
        \n    listall - List all groups \
        \n    list <group> - list the memebers of <group> \
        \n    listmemberships [addresses] - list group memberships for a list of addresses (or all if addresses are missing) \
        \n    add <group> <destination> <owner,manager> - add the <destination> to the <group> optionally as <owner> or <manager> \
        \n    addfromfile <group> <filen> <owner,manager> - add the emails listed in <file> to <group> optionally as <owner> or <manager> \
        \n    owner <group> <destination> - set <destination> to an owner of <group> \
        \n    manager <group> <destination> - set <destination> to a manager of <group> \
        \n    member <group> <destination> - set <destination> to member of <group> \
        \n    create <group> <type> - create <group> where <type> can be [alias, announce, discuss] \
        \n    delete <group> <destination> - delete the <destination> from the <group> \
        \n    groupdelete <group> - delete whole <group> WITHOUT CONFIRMATION \
        \n    getsettings <group> - output the settings for <group> \
        \n    updatesettings <group> <type> - update the settings of <group> to <type> \
        "
    parser = OptionParser(usage)

    parser.add_option('-d', '--domain', default=config_domain)
    parser.add_option('--auth_host_name', default='localhost',
                      help='Hostname when running a local web server.')
    parser.add_option('--noauth_local_webserver', action='store_true',
                      default=False, help='Do not run a local web server.')
    parser.add_option('--auth_host_port', default=[8080, 8090], type=int,
                      nargs='*', help='Port web server should listen on.')
    parser.add_option('--logging_level', default='ERROR',
                      choices=['DEBUG', 'INFO', 'WARNING', 'ERROR',
                               'CRITICAL'],
                      help='Set the logging level of detail.')
    group = OptionGroup(parser, "Dangerous Options",
                        "Caution: use these options at your own risk.  "
                        "It is believed that some of them bite.")

    options, args = parser.parse_args()

    if len(args) < 1:
        parser.error("incorrect number of arguments")
    else:
        command = args[0]

    if not options.domain:
        options.domain = raw_input("Google apps domain name: ")

    # Set up a Flow object to be used if we need to authenticate.
    scope = ("https://www.googleapis.com/auth/admin.directory.group"
             " "
             "https://www.googleapis.com/auth/admin.directory.group.member"
             " "
             "https://www.googleapis.com/auth/apps.groups.settings")
    FLOW = flow_from_clientsecrets(CLIENT_SECRETS,
                                   scope=scope,
                                   message=MISSING_CLIENT_SECRETS_MESSAGE)
    # Create an httplib2.Http object to handle our HTTP requests
    http = httplib2.Http()
    storage = Storage('credentials.dat')
    credentials = storage.get()

    if credentials is None or credentials.invalid:
        print 'invalid credentials'
        # Save the credentials in storage to be used in subsequent runs.
        credentials = run_flow(FLOW, storage, flags=options, http=http)

    # Authorize with our good Credentdials
    http = credentials.authorize(http)

    admin_service = build('admin', 'directory_v1', http=http)
    group_settings_service = build('groupssettings', 'v1', http=http)
    
    # Sanatize the input if possible
    if len(args) > 1 and args[1].endswith("."):
        print "removing trailing ."
        args[1] = args[1][:-1]
    if len(args) > 2 and args[2].endswith("."):
        print "removing trailing ."
        args[2] = args[2][:-1]
    if len(args) > 1 and not args[1].endswith(config_domain):
        args[1] = args[1] + "@" + config_domain
    # COMMANDS
    if len(args) > 2 and args[1] == args[2]:
        print "ERROR: Group and destination are the same, exiting."
    elif command == "listall":
        print_all_members(admin_service, config_domain)
    elif command == "list":
        print "listing group", args[1]
        list_group(admin_service, args[1])
    elif command == "listmemberships":
        print "listing group memberships"
        if len(args) == 1:
            print_list_memberships(admin_service, config_domain, [])
        else:
            print_list_memberships(admin_service, config_domain, args[1:])
    elif command == "add":
        role = "MEMBER"
        if len(args) == 4:
            if string.lower(args[3]) == "owner" or args[3] == "manager":
                print "%s add %s as %s" % (args[1], args[2], args[3])
                role = args[3]
            else:
                print "You can only set people as owner or manager or leave blank for normal member."                
        else:
            print "%s add %s" % (args[1], args[2])

        add_to_group(admin_service, group_settings_service, args[1], args[2], role.upper())
    elif command == "addfromfile":
        role = "MEMBER"
        if len(args) == 4:
            if args[3].lower() == "owner" or args[3] == "manager":
                print "%s addusers from %s as %s" % (args[1], args[2], args[3])
                role = args[3]
            else:
                print "You can only set people as owner or manager or leave blank for normal member."
        else:
            print "%s add users from %s" % (args[1], args[2])
        if not os.stat(args[2]).st_size == 0:
            add_to_group_from_file(admin_service, group_settings_service, args[1], args[2], role.upper())
        else:
            print "Skipping empty file"
    elif command == "owner":
        print "%s set %s to owner" % (args[1], args[2])
        delete_from_group(admin_service, args[1], args[2], nopurge=True, quiet=True)
        add_to_group(admin_service, group_settings_service, args[1], args[2], role="OWNER")
    elif command == "manager":
        print "%s set %s to manager" % (args[1], args[2])
        delete_from_group(admin_service, args[1], args[2], nopurge=True, quiet=True)
        add_to_group(admin_service, group_settings_service, args[1], args[2], role="MANAGER")
    elif command == "member":
        print "%s set %s to member" % (args[1], args[2])
        delete_from_group(admin_service, args[1], args[2], nopurge=True, quiet=True)
        add_to_group(admin_service, group_settings_service, args[1], args[2], role="MEMBER")
    elif command == "delete":
        if len(args) < 3:
            print "ERROR: Missing <destination>. Use groupdelete to delete the whole group."
        else :
            print "%s delete %s" % (args[1], args[2])
            delete_from_group(admin_service, args[1], args[2])
    elif command == "groupdelete":
        remove_group(admin_service, args[1])
        print args[1] + " deleted"
    elif command == "create":
        print "Creating %s as %s" % (args[1], args[2])
        create_group(admin_service, group_settings_service, args[1], args[2])
    elif command == "updatesettings":
        update_group_settings(admin_service, group_settings_service, args[1], args[2])
    elif command == "getsettings":
        print_group_settings(group_settings_service, args[1])
    else:
        print "Unknown command"


if __name__ == '__main__':
    main(sys.argv)
