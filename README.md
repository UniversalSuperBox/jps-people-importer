# jps-people-importer

This script creates users in a JAMF Pro Server instance from an LDAP query.

This is a workaround for an issue where the JPS immediately unmanages devices signed into by users who do not exist in its user database.

The script creates users with their username set to their LDAP `sAMAccountName`, email set to the `mail` attribute, and the name '`sn`, `givenName`'.

The script prints status information and errors to stderr and the usernames it imports, one per line, to stdout.

## Prerequisites

To use jps-people-importer, you will need Python3 and pipenv installed.

### Install Python

#### macOS

To install Python3 on macOS, download the pkg from https://www.python.org/downloads/. Once you've run and installed the pkg, find "Python 3.*x*" in your Applications directory and run the `Update Shell Profile.command` file, then the `Install Certificates.command` file.

#### Windows

To install Python3 on Windows, download its installer from https://www.python.org/downloads/. While installing, check the option to add Python to your PATH. Once the installation completes, reboot your computer so Python can be run from a command prompt.

### Install Pipenv

Pipenv is used to install the dependencies for jps-people-importer and keep them separate from any other Python projects on your computer. To install pipenv, run the following command in a terminal or command prompt:

```
pip3 install --user pipenv
```

## Usage

### Download jps-people-importer

You can download the script and its example configuration by selecting "Download ZIP" under the Clone or Download menu, clicking [this link](https://github.com/UniversalSuperBox/jps-people-importer/archive/master.zip), or cloning it with `git`.

### Configure jps-people-importer

To start, copy `conf.py.example` to `conf.py`.

Then, you may either edit the `conf.py` file to enter your desired values (replacing the `environ[...]` portions of the configuration) or set the values in your shell environment before running the script.

To set the configuration environment variables under most shells, type `export VARIABLE_NAME=value`, where VARIABLE_NAME is the part within quotes in the `conf.py` script. For example, to provide LDAP_FILTER to the script exclusively from the environment, type:

```
export LDAP_FILTER=(&(objectcategory=person)(objectclass=user))
```

Under a Windows shell, replace `export` with `set`.

Unless otherwise specified in this section, the environment variable used to set a configuration option uses the same name as the configuration option itself. `LDAP_FILTER` in the config file can be set as `LDAP_FILTER` in the environment, for example.

#### LDAP_FILTER

This filter is run against each LDAP DN in the LDAP_SEARCH_DN_LIST to retrieve a list of users to add to the JPS. "(&(objectcategory=person)(objectclass=user))" should retrieve only the user objects in an Active Directory domain.

#### LDAP_SEARCH_DN_LIST

This list contains all of the base-level objects that you would like to search for users within. One search (filtered by LDAP_FILTER) will be initiated for each object in this list. For example, suppose your Active Directory domain is located at mydomain.tld and you would like to search the OUs "Students" and "Staff" for users. In this case, you would enter:

```python
LDAP_SEARCH_DN_LIST = [
    "OU=Students,DC=mydomain,DC=tld",
    "OU=Staff,DC=mydomain,DC=tld",
]
```

A single search DN may be specified in the environment as `LDAP_SEARCH_DN`

#### LDAP_BIND_URI

This URI points to your LDAP server. For an Active Directory domain, you probably want to use 'ldaps://mydomain.tld:636'.

#### LDAP_INSECURE

If you use 'ldaps://' and you do not use a valid certificate for your LDAP server, set LDAP_INSECURE to True. Certificate checking for your LDAP server will occur if LDAP_INSECURE is set to False. It is False by default.

This value may be specified in the environment as `LDAP_INSECURE`. If it is set to `1`, LDAP_INSECURE is considered True. If it is unset, LDAP_INSECURE is set to False.

#### LDAP_BIND_USERNAME and LDAP_BIND_PASSWORD

These values specify the username and password used to bind to your LDAP directory. For an Active Directory domain, you will probably use `mydirectory\username` for `LDAP_BIND_USERNAME`.

#### JAMF_URL

This URL points to the base of your JPS. For example, `https://jps.mydomain.tld:8443`.

#### JAMF_USERNAME and JAMF_PASSWORD

These values specify the username and password used to sign in to the JPS. The user account must have user/read and user/create permissions.

### Run jps-people-importer

Change into the script's directory. With the script configured and its dependencies installed, it can be run with:

```
pipenv install --three
pipenv run python ./jps-people-importer.py
```
