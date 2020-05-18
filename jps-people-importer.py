"""
This script creates users in a JAMF Pro Server instance from an LDAP query.
"""

# Copyright 2020 Dalton Durst
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import sys
from collections import namedtuple
from multiprocessing.pool import ThreadPool
from typing import List

import ldap
import requests
from ldap.controls import SimplePagedResultsControl

from conf import (
    JAMF_PASSWORD,
    JAMF_URL,
    JAMF_USERNAME,
    LDAP_BIND_PASSWORD,
    LDAP_BIND_URI,
    LDAP_BIND_USERNAME,
    LDAP_FILTER,
    LDAP_INSECURE,
    LDAP_SEARCH_DN_LIST,
)

JAMF_AUTH = requests.auth.HTTPBasicAuth(JAMF_USERNAME, JAMF_PASSWORD)

SESSION = requests.Session()

User = namedtuple("User", ["sAMAccountName", "email", "last_name", "first_name"])


def eprint(*args, **kwargs):
    """Like print, but outputs to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def results_for_dn(directory: ldap.ldapobject, base_dn: str, filter: str) -> List[User]:
    """Returns a list of User objects found in the directory object for filter

    :param directory: A ldap.LDAPObject that has already been bound to a
        directory.

    :param base_dn: The base of the directory tree to run the search filter
        against.

    :param filter: The LDAP search filter to run on base_dn using directory.
    """
    req_ctrl = SimplePagedResultsControl(True, size=5000, cookie="")

    known_ldap_resp_ctrls = {
        SimplePagedResultsControl.controlType: SimplePagedResultsControl,
    }

    # Send search request
    msgid = directory.search_ext(
        base_dn, ldap.SCOPE_SUBTREE, filterstr=LDAP_FILTER, serverctrls=[req_ctrl]
    )

    results = []
    while True:
        __, result_data, __, serverctrls = directory.result3(
            msgid, resp_ctrl_classes=known_ldap_resp_ctrls
        )

        results.extend(
            [
                User(
                    ldap_entry["sAMAccountName"][0].decode(),
                    ldap_entry["mail"][0].decode(),
                    ldap_entry["sn"][0].decode(),
                    ldap_entry["givenName"][0].decode(),
                )
                for __, ldap_entry in result_data
            ]
        )

        page_controls = [
            control
            for control in serverctrls
            if control.controlType == SimplePagedResultsControl.controlType
        ]
        if page_controls:
            if page_controls[0].cookie:
                # Copy cookie from response control to request control
                req_ctrl.cookie = page_controls[0].cookie
                msgid = directory.search_ext(
                    base_dn,
                    ldap.SCOPE_SUBTREE,
                    filterstr=LDAP_FILTER,
                    serverctrls=[req_ctrl],
                )
            else:
                break
        else:
            eprint("Warning: Server ignores RFC 2696 control.")
            break

    return results


def create_user_in_jamf(user: User):
    """ Creates a user in the JPS

    :param user: A User object which will be used to create the JPS user.

    This function uses the following module variables:

    * SESSION must be a requests.Session instance
    * JAMF_AUTH must be a requests.auth interface instance
    * JAMF_URL must be the full base URL of a JAMF instance.
    """

    xml = """
        <user>
            <name>{name}</name>
            <full_name>{last_name}, {first_name}</full_name>
            <email>{email}</email>
        </user>
    """.format(
        name=user.sAMAccountName,
        last_name=user.last_name,
        first_name=user.first_name,
        email=user.email,
    ).encode()

    r = SESSION.post(
        JAMF_URL + "/JSSResource/users/id/-1",
        data=xml,
        headers={"Content-Type": "application/xml", "Accept": "application/xml"},
        auth=JAMF_AUTH,
    )

    try:
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        eprint("Failed to create user with username", user.sAMAccountName)
        eprint(e)
        eprint(r.text)
    else:
        print(user.sAMAccountName)


def main():
    eprint("Binding to LDAP...")
    if LDAP_INSECURE:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    directory = ldap.initialize(LDAP_BIND_URI)
    directory.protocol_version = 3
    directory.simple_bind_s(who=LDAP_BIND_USERNAME, cred=LDAP_BIND_PASSWORD)

    eprint("Searching directory for users...")
    ldap_users = []
    for base_dn in LDAP_SEARCH_DN_LIST:
        ldap_users.extend(results_for_dn(directory, base_dn, LDAP_FILTER))

    directory.unbind_s()
    directory = None

    eprint("Total LDAP users:", len(ldap_users))
    eprint("Asking JPS for its user list...")

    jamf_user_request = requests.get(
        JAMF_URL + "/JSSResource/users",
        auth=JAMF_AUTH,
        headers={"Accept": "application/json"},
    )
    jamf_user_json = jamf_user_request.json()

    jamf_usernames = frozenset([user["name"] for user in jamf_user_json["users"]])

    eprint("Total JAMF users:", len(jamf_usernames))

    missing_users = [
        user for user in ldap_users if user.sAMAccountName not in jamf_usernames
    ]

    eprint("Users to create:", len(missing_users))

    with ThreadPool(10) as pool:
        results = pool.map(create_user_in_jamf, missing_users)

    eprint("Done. Created users:", len(results))


if __name__ == "__main__":
    main()
