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
import simplejson
import os.path
import ConfigParser
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
VALID_GROUP_TYPES = ["alias", "announce", "discussion"]

# API Reference for settings at
# https://developers.google.com/admin-sdk/groups-settings/v1/reference/groups

# Global settings for all lists
globalSettings = {}
globalSettings['sendMessageDenyNotification'] = 'false'
globalSettings['description'] = ''

# Fuck it, I've tried everything and I can't find a valid value for english --Trevor
# globalSettings['primaryLanguage'] = 'en-US'

# Alias specific settings
aliasSettings = globalSettings
aliasSettings['whoCanPostMessage'] = 'ANYONE_CAN_POST'
aliasSettings['messageModerationLevel'] = 'MODERATE_NONE'
aliasSettings['maxMessageBytes'] = '10240000'
aliasSettings['spamModerationLevel'] = 'ALLOW'
aliasSettings['showInGroupDirectory'] = 'false'
aliasSettings['isArchived'] = 'false'

# Discussion specific settings
discussionSettings = globalSettings
discussionSettings['whoCanPostMessage'] = 'ALL_MEMBERS_CAN_POST'
discussionSettings['messageModerationLevel'] = 'MODERATE_NONE'
discussionSettings['spamModerationLevel'] = 'MODERATE'
discussionSettings['showInGroupDirectory'] = 'true'
discussionSettings['isArchived'] = 'true'

# Announce specific settings
announceSettings = globalSettings
announceSettings['whoCanPostMessage'] = 'ALL_MEMBERS_CAN_POST'
announceSettings['messageModerationLevel'] = 'MODERATE_ALL_MESSAGES'
announceSettings['spamModerationLevel'] = 'MODERATE'
announceSettings['showInGroupDirectory'] = 'true'
announceSettings['isArchived'] = 'true'

def retry_if_http_error(exception):
    """Return True if we should retry  False otherwise"""
    return isinstance(exception, HttpError)

# Implement backoff in case of API rate errors
# @retry(wait_exponential_multiplier=1000,
#        wait_exponential_max=10000,
#        retry_on_exception=retry_if_http_error,
#        wrap_exception=False)
def execute_with_backoff(request):
    response = request.execute()
    return response


def query_group_type():
    valid = {"l": "alias", "L": "alias", "Alias": "alias", "alias": "alias",
             "d": "discussion", "D": "discussion", "Discussion": "discussion", "discussion": "discussion",
             "n": "announce", "N": "announce", "Announce": "announce", "announce": "announce"}

    prompt = " [L/D/N] "

    while True:
        sys.stdout.write("Is this group aLias, aNnounce or Disccusion" + prompt)
        choice = raw_input().lower()
        if choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'alias' or 'announce' or 'discussion' "
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

    group_service = admin_service.groups()
    body = {}
    body['email'] = group_id
    body['name'] = group_id.split("@", 1)[0].title() + " " + group_type.title()

    request = group_service.insert(body=body)
    group = request.execute()

    if group_type is "alias":
        settings = aliasSettings
    elif group_type is "announce":
        settings = announceSettings
    elif group_type is "discussion":
        settings = discussionSettings

    settings_service = group_settings_service.groups()
    request = settings_service.patch(groupUniqueId=group_id, body=settings)
    settings = request.execute()
    return group


def remove_group(admin_service, groupUniqueId):
    group_service = admin_service.groups()
    request = group_service.delete(groupKey=groupUniqueId)
    response = request.execute()
    return response


def add_group_member(admin_service, group_email, email_address, owner):
    member_service = admin_service.members()
    myRole = "MEMBER"
    if owner:
        myRole = "OWNER"
    request = member_service.insert(groupKey=group_email, body={'email': email_address, 'role': myRole})
    response = request.execute()
    return response


def remove_group_member(admin_service, email_address, group_email):
    member_service = admin_service.members()
    request = member_service.delete(groupKey=group_email,
                                    memberKey=email_address)
    response = request.execute()
    return response


def is_group_member(admin_service, email_address, group_email):
    try:
        member_service = admin_service.members()
        request = member_service.get(groupKey=group_email,
                                     memberKey=email_address)
        response = request.execute()
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


def print_members(admin_service, group_email):
    gid = ""
    members = get_group_members(admin_service, group_email)
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


def add_to_group(admin_service, group_settings_service, groupid, address, owner=False):
    try:
        group_service = admin_service.groups()
        request = group_service.get(groupKey=groupid)
        group = request.execute()
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
        add_group_member(admin_service, groupid, address, owner)
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
            print '%s is already a member of %s' % (address, groupid)
        else:
            print 'Error code: %d' % error.get('code')
            print 'Error message: %s' % error.get('message')
            print 'Error reason: %s' % error['errors'][0]['reason']
            raise e

    print "Current status of group"
    print_group(admin_service, group)


def delete_from_group(admin_service, groupid, address):
    try:
        group_service = admin_service.groups()
        request = group_service.get(groupKey=groupid)
        group = request.execute()
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
        if not response:
            print "Deleted"
        else:
            print "Error: There was a problem removing the group member"

    members = get_group_members(admin_service, groupid)
    if not members:
        answer = query_yes_no("Group empty, delete it?")
        if answer:
            if not remove_group(admin_service, group['id']):
                print "group empty, removing group"
            else:
                print "Error removing group"
        else:
            print "Leaving empty group"
    else:
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
        \n    list <group> - list the specified group \
        \n    list_memberships [addresses] - list group memberships for a list of addresses (or all if addresses are missing) \
        \n    add <group> <destination> <owner> - add the <destination> to the <group> optionally you can specify owner \
        \n    promote <group> <destination> - promote <destination> to an owner of <group> \
        \n    demote <group> <destination> - demote <destination> to member of <group> \
        \n    create <group> <type> - create a group where type can be [alias, announce, discussion] \
        \n    delete <group> <destination> - delete the <destination> from the <group> \
        \n    getsettings <group> - output the settings for <group> \
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

    # COMMANDS

    if command == "listall":
        print_all_members(admin_service, config_domain)
    elif command == "list":
        print "listing group", args[1]
        list_group(admin_service, args[1])
    elif command == "list_memberships":
        print "listing group memberships"
        if len(args) == 1:
            print_list_memberships(admin_service, config_domain, [])
        else:
            print_list_memberships(admin_service, config_domain, args[1:])
    elif command == "add":
        owner = False
        if len(args) == 4:
            if args[3] == "owner":
                print "%s add %s as owner" % (args[1], args[2])
                owner = True
        else:
            print "%s add %s" % (args[1], args[2])

        add_to_group(admin_service, group_settings_service, args[1], args[2], owner)
    elif command == "promote":
        print "%s promote %s" % (args[1], args[2])
        delete_from_group(admin_service, args[1], args[2])
        add_to_group(admin_service, group_settings_service, args[1], args[2], True)
    elif command == "demote":
        print "%s demote %s" % (args[1], args[2])
        delete_from_group(admin_service, args[1], args[2])
        add_to_group(admin_service, group_settings_service, args[1], args[2], False)
    elif command == "delete":
        print "%s delete %s" % (args[1], args[2])
        delete_from_group(admin_service, args[1], args[2])
    elif command == "create":
        create_group(admin_service, group_settings_service, args[1], args[2])
    elif command == "getsettings":
        print_group_settings(group_settings_service, args[1])
    else:
        print "Unknown command"


if __name__ == '__main__':
    main(sys.argv)
