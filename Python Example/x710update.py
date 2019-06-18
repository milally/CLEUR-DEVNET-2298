# Copyright 2018 Cisco Systems, Inc.
# Author: Michael S. Lally, Customer Solutions Architect, Cisco
# Email: milally<at>cisco.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script logs into the CIMC of a UCS C-series server, mounts a
# remote IMG file of the Intel(R) Ethernet Flash Firmware Utility
# (BootUtil), and using the Serial Over LAN (SOL) interface uses the
# UEFI shell to enable PXE boot in Legacy BIOS mode for the Intel(R)
# NICs present in the system.
#
# usage: python x710update.py [options]
# OR
# python x710update.py -i "IP Address" -u "UserName" -p "Password"
# OR
# python x710update.py -f \path\to\file.csv
#
#options:
#  -h, --help            show this help message and exit
#  -i IP, --ip=IP        [Required if not using -f] IMC IP Address
#  -u USERNAME, --username=USERNAME
#                        [Required if not using -f] Account Username for IMC Login
#  -p PASSWORD, --password=PASSWORD
#                        [Optional] Account Password for IMC Login
#  -f FILENAME, --filename=FILENAME
#                        [Optional] Path to CSV file containing list of IP, user, password
#                        for multiple IMC devices

import csv
import getpass
import logging
import optparse
import os
import pexpect
import platform
import re
import socket
import subprocess
import sys
import threading
import time

from imcsdk import imcmethodfactory
from imcsdk.apis.admin.ipmi import _get_comm_mo_dn
from imcsdk.apis.utils import _is_valid_arg
from imcsdk.imccoreutils import get_server_dn, IMC_PLATFORM, _set_server_dn
from imcsdk.imcexception import ImcOperationError
from imcsdk.imchandle import ImcHandle
from imcsdk.mometa.comm.CommVMedia import CommVMedia
from imcsdk.mometa.comm.CommVMediaMap import CommVMediaMap
from imcsdk.mometa.compute.ComputeRackUnit import ComputeRackUnit,\
        ComputeRackUnitConsts
from imcsdk.mometa.compute.ComputeServerNode import ComputeServerNodeConsts
from imcsdk.mometa.equipment.EquipmentChassis import EquipmentChassis
from imcsdk.mometa.sol.SolIf import SolIfConsts
from Queue import Queue

try:
    from urllib.parse import urlsplit
except ImportError:
    from urlparse import urlsplit

handleList = []
ip = ""
user = ""
url = ""
volume_name="bootutil"
bios_changed = ""

CIFS_URI_PATTERN = re.compile('^//\d+\.\d+\.\d+\.\d+\/')
NFS_URI_PATTERN = re.compile('^\d+\.\d+\.\d+\.\d+\:\/')


def CheckHostOS():
    if platform.system() == "Windows" or platform.system() == "Microsoft":
        try:
            import win_inet_pton
        except ImportError:
            print "It appears you are on a Windows machine. Please install the win_inet_pton library.\n"
            return None


def GetPassword(prompt):
    if platform.system() == "Linux":
        return getpass.unix_getpass(prompt=prompt)
    elif platform.system() == "Windows" or platform.system() == "Microsoft":
        return getpass.win_getpass(prompt=prompt)
    else:
        return getpass.getpass(prompt=prompt)

def QueryYesNo(question, default="yes"):
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
        raise ValueError("Invalid default answer: '%s'" % default)

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

def DoLogin(ip, user, pwd):
    log = logging.getLogger()
    log.info("Connecting to IMC Server <%s>....\n", ip)
    print "Connecting to IMC Server <%s>....\n" %(ip)
    handle = ImcHandle(ip,user,pwd)
    if handle.login(auto_refresh=True):
        log.info("Login successful: <%s>\n", handle._ImcSession__imc)
        print "Login successful: <%s>\n" %(handle._ImcSession__imc)
        handleList.append(handle)
        return handle


def DoLogout(handle):
    log = logging.getLogger()
    if handle in handleList:
        handleName = handle._ImcSession__imc
        if handle.logout():
            log.info("Logout successful: <%s>\n", handleName)
            print "\nLogout successful: <%s>\n" %(handleName)


def IsValidIpv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(ip)
        except socket.error:
            return False
        return ip.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True


def PingTest(ip):
    try:
        cmd = "ping -{} 1 {}".format('n' if platform.system() == "Windows" or platform.system() == "Microsoft" else 'c', ip)
        pingresult = subprocess.Popen(cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT).communicate()[0]
        if ('ttl=' in pingresult) or ('TTL=' in pingresult): # a ttl means we have a positive response
            return True
        else:
            return False
    except OSError:
        log.error("Unable to ping the IP address  %s  due to a system error.\n", ip)
        print "ERROR: Unable to ping the IP address " + ip + " due to a system error.\n"


def _get_bios_dn(handle, server_id=1):
    server_dn = get_server_dn(handle, server_id)
    return (server_dn + '/bios')


def _get_bios_profile_mo(handle, name, server_id=1):
    bios_dn = _get_bios_dn(handle, server_id)
    parent_dn = bios_dn + '/profile-mgmt'
    mos = handle.query_children(in_dn=parent_dn)
    for mo in mos:
        if mo._class_id == 'BiosProfile' and mo.name == name:
            return mo
    return None


def _get_bios_mo_table(handle, tokens={}, server_id=1):
    from imcsdk.imcbiostables import bios_tokens_table

    mo_table = {}

    for token, value in tokens.items():
        bios_tokens_table_platform = bios_tokens_table.get(handle.platform,
                                                           bios_tokens_table[
                                                               'classic'])
        entry = bios_tokens_table_platform.get(token)
        if entry is None:
            continue

        mo_props = mo_table.get(entry["mo_name"], {})
        mo_props[entry["prop_name"]] = value
        mo_table[entry["mo_name"]] = mo_props

    return mo_table


def _get_bios_profile(handle, name, server_id=1):
    mo = _get_bios_profile_mo(handle, name=name, server_id=server_id)
    if mo is None:
        raise ImcOperationError("Get BiosProfile: %s " % name,
                                "Managed Object not found")
    return mo


def bios_profile_backup_running(handle, server_id=1, **kwargs):
    """
    Backups up the running configuration of various bios tokens to create a
    'cisco_backup_profile'.
    Will overwrite the existing backup profile if it exists.
    Args:
        handle (ImcHandle)
        server_id (int): Id of the server to perform
                         this operation on C3260 platforms
        kwargs : Key-Value paired arguments for future use
    Returns:
        BiosProfile object corresponding to the backup profile created
    Raises:
        ImcOperationError if the backup profile is not created
    Examples:
        bios_profile_backup_running(handle, server_id=1)
    """

    from imcsdk.mometa.bios.BiosProfileManagement import BiosProfileManagement
    from imcsdk.mometa.bios.BiosProfileManagement import \
        BiosProfileManagementConsts

    mo = BiosProfileManagement(parent_mo_or_dn=_get_bios_dn(handle, server_id))
    mo.admin_action = BiosProfileManagementConsts.ADMIN_ACTION_BACKUP
    mo.set_prop_multiple(**kwargs)
    handle.set_mo(mo)

    return _get_bios_profile(handle, name='cisco_backup_profile')



def bios_profile_upload(handle, uri,
                        user=None, pwd=None, server_id=1, **kwargs):
    """
    Uploads a user configured bios profile in json format.
    Cisco IMC supports uploading a maximum of 3 profiles
    Valid protocls for upload are ['tftp', 'ftp', 'http', 'scp', 'sftp']
    Args:
        handle (ImcHandle)
        uri (str): URI for remotely accessing the file
        server_id (int): Id of the server to perform
                         this operation on C3260 platforms
        kwargs: Key-Value paired arguments for future use
    Returns:
        UploadBiosProfile object
    Examples:
        bios_profile_upload(handle, uri='http://server/file.json',
                        user='abcd', pwd='pqrs')
    """

    from imcsdk.mometa.upload.UploadBiosProfile import UploadBiosProfile
    bios_dn = _get_bios_dn(handle, server_id=server_id)
    mo = UploadBiosProfile(
            parent_mo_or_dn=bios_dn + '/profile-mgmt')

    # Parse file/path from URI
    #remote_file = os.path.basename(uri)
    remote_file = urlsplit(uri).path
    #remote_server = os.path.dirname(uri) + "/"
    remote_server = urlsplit(uri).netloc

    # Set the Map based on the protocol
    if urlsplit(uri).scheme == 'http':
        protocol = "http"
    elif urlsplit(uri).scheme == 'https':
        protocol = "http"
    elif urlsplit(uri).scheme == 'scp':
        protocol = "scp"
    elif urlsplit(uri).scheme == 'sftp':
        protocol = "sftp"
    elif urlsplit(uri).scheme == 'tftp':
        protocol = "tftp"
    elif urlsplit(uri).scheme == 'ftp':
        protocol = "ftp"
    else:
        # Raise ValueError and bail
        raise ValueError("Unsupported protocol: " +
                         urlsplit(uri).scheme)

    # Convert no user/pass to blank strings
    if not user:
        user = ''
    if not pwd:
        pwd = ''
    params = {
        'remote_server': remote_server,
        'remote_file': remote_file,
        'protocol': protocol,
        'user': user,
        'pwd': pwd
    }
    mo.set_prop_multiple(**params)
    mo.set_prop_multiple(**kwargs)
    handle.set_mo(mo)
    return handle.query_dn(mo.dn)


def bios_profile_get(handle, name, server_id=1):
    """
    Gets the bios profile corresponding to the name specified
    Args:
        handle (ImcHandle)
        name (str): Name of the bios profile.
                    Corresponds to the name field in the json file.
        server_id (int): Id of the server to perform
                         this operation on C3260 platforms
    Returns:
        BiosProfile object corresponding to the name specified
    Raises:
        ImcOperationError if the bios profile is not found
    Examples:
        bios_profile_get(handle, name='simple')
    """

    return _get_bios_profile_mo(handle, name=name, server_id=server_id)


def bios_profile_activate(handle, name, backup_on_activate=True,
                          reboot_on_activate=False, server_id=1, **kwargs):
    """
    Activates the bios profile specified by name on the Cisco IMC Server
    Args:
        handle (ImcHandle)
        name (str): Name of the bios profile.
                    Corresponds to the name field in the json file.
        backup_on_activate (bool): Backup running bios configuration
                                   before activating this profile.
                                   Will overwrite the previous backup.
        reboot_on_activate (bool): Reboot the host/server for the newer bios
                                   configuration to be applied.
        server_id (int): Id of the server to perform
                         this operation on C3260 platforms.
        kwargs: Key-Value paired arguments for future use.
    Returns:
        BiosProfile object corresponding to the name specified
    Raises:
        ImcOperationError if the bios profile is not found
    Examples:
        bios_profile_activate(handle, name='simple',
                              backup_on_activate=True,
                              reboot_on_activate=False)
    """

    from imcsdk.mometa.bios.BiosProfile import BiosProfileConsts
    mo = _get_bios_profile(handle, name=name, server_id=server_id)
    params = {
        'backup_on_activate': ('no', 'yes')[backup_on_activate],
        'reboot_on_activate': ('no', 'yes')[reboot_on_activate],
        'enabled': 'yes',
        'admin_action': BiosProfileConsts.ADMIN_ACTION_ACTIVATE
    }
    mo.set_prop_multiple(**params)
    mo.set_prop_multiple(**kwargs)
    handle.set_mo(mo)
    return handle.query_dn(mo.dn)


def bios_profile_delete(handle, name, server_id=1):
    """
    Deletes the bios profile specified by the name on the Cisco IMC server
    Args:
        handle (ImcHandle)
        name (str): Name of the bios profile.
                    Corresponds to the name field in the json file.
        server_id (int): Id of the server to perform
                         this operation on C3260 platforms.
    Returns:
        None
    Raises:
        ImcOperationError if the bios profile is not found
    Examples:
        bios_profile_delete(handle, name='simple', server_id=2)
    """
    from imcsdk.mometa.bios.BiosProfile import BiosProfileConsts
    mo = _get_bios_profile(handle, name=name, server_id=server_id)
    mo.admin_action = BiosProfileConsts.ADMIN_ACTION_DELETE
    handle.set_mo(mo)


def bios_tokens_exist(handle, tokens={}, server_id=1):
    """
    Args:
        handle (ImcHandle)
        tokens (dictionary) : (key, value) pair of bios tokens with key being the name of the token
        server_id (int): Id of the server to perform
                         this operation on C3260 platforms.
    Returns:
        True/False based on the match with the server side tokens
    Examples:
        bios_tokens_exist(handle,
                          tokens = {
                            "BaudRate": "19200",
                            "IntelVTDATSSupport": "enabled",
                            "ConsoleRedirection": "com-1",
                            "FlowControl": "rts-cts"},
                          server_id=2)
"""

    parent_dn = _get_bios_dn(handle, server_id) + "/bios-settings"
    mo_table = _get_bios_mo_table(handle, tokens, server_id)

    for mo_name, props in mo_table.items():
        cimc_mos = handle.query_classid(class_id=mo_name)
        cimc_mo = None
        for mo in cimc_mos:
            if mo.dn.startswith(parent_dn):
                cimc_mo = mo
                break

        if cimc_mo is None:
            return False

        # Skip comparison when the value to be checked with is "platform-default"
        modified_props = {x: props[x] for x in props if props[x] != "platform-default"}

        if not cimc_mo.check_prop_match(**modified_props):
            return False

    return True


def is_bios_profile_enabled(handle, name, server_id=1):
    """
    Args:
        handle (ImcHandle)
        name (str): Name of the bios profile.
                    Corresponds to the name field in the json file.
        server_id (int): Id of the server to perform
                         this operation on C3260 platforms.
    Returns:
        bool
    Raises:
        ImcOperationError if the bios profile is not found
    Examples:
        is_bios_profile_enabled(handle,
                                name='simple',
                                server_id=1)
    """
    mo = _get_bios_profile(handle, name=name, server_id=server_id)
    return mo.enabled.lower() in ['yes', 'true']


def _get_vmedia_mo_dn(handle, server_id=1):
    return _get_comm_mo_dn(handle, server_id) + "/vmedia-svc"


def vmedia_enable(handle, encryption_state=None, low_power_usb=None,
                  server_id=1):
    """
    This method will enable vmedia and setup the properties
    Args:
        handle (ImcHandle)
        encrypt (bool): Encrypt virtual media communications
        low_power_usb (bool): Enable low power usb
        server_id (int): Server Id to be specified for C3260 platforms
    Returns:
        CommVMedia object
    Examples:
        vmedia_enable(handle, True, True)
    """

    mo = CommVMedia(parent_mo_or_dn=_get_comm_mo_dn(handle, server_id))
    params = {
        "admin_state": "enabled",
        "encryption_state": encryption_state,
        "low_power_usb_state": low_power_usb,
        "low_power_usb": low_power_usb,
    }

    mo.set_prop_multiple(**params)
    handle.set_mo(mo)
    return mo


def vmedia_get_existing_uri(handle, server_id=1):
    """
    This method will return list of URIs of existing mountd media
    Args:
        handle (ImcHandle)
        server_id (int): Server Id to be specified for C3260 platforms
    Returns:
        List of URIs of currently mounted virtual media
    Examples:
        vmedia_get_existing_uri(handle)
    """
    # Create list of URIs of all current virtually mapped ISOs

    vmedias = handle.query_children(in_dn=_get_vmedia_mo_dn(handle, server_id))
    return [vmedia.remote_share + vmedia.remote_file for vmedia in vmedias]


def vmedia_get_existing_status(handle, server_id=1):
    """
    This method will return list of status of existing mountd media
    Args:
        handle (ImcHandle)
        server_id (int): Server Id to be specified for C3260 platforms
    Returns:
        List of Status of currently mounted virtual media
    Examples:
        vmedia_get_existing_status(handle)
    """
    # Create list of URIs of all current virtually mapped ISOs
    vmedias = handle.query_children(in_dn=_get_vmedia_mo_dn(handle, server_id))
    return [vmedia.mapping_status for vmedia in vmedias]


def vmedia_mount_get(handle, volume_name, server_id=1):
    parent_dn = _get_vmedia_mo_dn(handle, server_id)
    dn = parent_dn + "/vmmap-" + volume_name
    mo = handle.query_dn(dn)
    if mo is None:
        raise ImcOperationError("vmedia_mount_get",
                                "vmedia mount '%s' does not exist" % dn)
    return mo


def vmedia_mount_create(handle, volume_name, remote_share, remote_file,
                        map="www", mount_options="noauto", username="",
                        password="", server_id=1, timeout=60):
    """
    This method will setup the vmedia mapping
    Args:
        handle (ImcHandle)
        volume_name (string): Name of the volume or identity of the image
        map (string): "cifs", "nfs", "www"
        mount_options (string): Options to be passed while mounting the image
        remote_share (string): URI of the image
        remote_file (string): name of the image
        username (string): username
        password (string): password
        server_id (int): Server Id to be specified for C3260 platforms
    Returns:
        CommVMediaMap object
    Examples:
        vmedia_mount_add(
            handle,
            volume_name="c",
            map="www",
            mount_options="noauto", "nolock" etc.
            remote_share="http://1.1.1.1/files",
            remote_file="ubuntu-14.04.2-server-amd64.iso",
            username="abcd",
            password="xyz")
    """
    image_type = remote_file.split('.')[-1]
    vmedia_mount_remove_image(handle, image_type)

    mo = CommVMediaMap(parent_mo_or_dn=_get_vmedia_mo_dn(handle, server_id),
                       volume_name=volume_name)
    mo.map = map
    if mount_options:
        mo.mount_options = mount_options
    mo.remote_share = remote_share
    mo.remote_file = remote_file
    mo.username = username
    mo.password = password

    handle.add_mo(mo, modify_present="True")

    wait_time = 0
    interval = 10
    while wait_time < timeout:
        time.sleep(interval)
        mo = handle.query_dn(mo.dn)
        existing_mapping_status = mo.mapping_status
        if existing_mapping_status == "OK":
            return mo
        elif re.match(r"ERROR", existing_mapping_status):
            raise ImcOperationError("vmedia_mount_create",
                                    mo.mapping_status)
        wait_time += interval

    raise ImcOperationError("vmedia_mount_create",
                            "ERROR - Mapped image status stuck at %s" %
                            existing_mapping_status)


def vmedia_mount_exists(handle, volume_name, server_id=1, **kwargs):
    import re

    try:
        mo = vmedia_mount_get(handle, volume_name)
    except ImcOperationError:
        return False, None

    kwargs.pop('timeout', None)
    kwargs.pop('password', None)
    username = kwargs.pop('username', None)
    mount_options = kwargs.pop('mount_options', None)

    if not mo.check_prop_match(**kwargs):
        return False, None

    mo_mount_options = [x.strip() for x in mo.mount_options.split(',')]

    if mount_options:
        mount_options = [x.strip() for x in mount_options.split(',')][0]
        if mount_options not in mo_mount_options:
            return False, None

    if username and mo.map in ['cifs', 'www']:
        mo_username = re.search(r'username=(\S*?),',
                                mo.mount_options).groups()[0]
        if username != mo_username:
            return False, None

    if mo.mapping_status != 'OK':
        return False, None

    return True, mo


def vmedia_mount_uri(handle, uri, volume_name=None, user_id=None,
                         password=None, timeout=60, interval=5, server_id=1):
    """
    This method will setup the vmedia mapping
    Args:
        handle (ImcHandle)
        uri (string): URI of the image
        volume_name (string): optional name of volume
        user_id (string): optional username
        password (string): optional password
        timeout (int): optional timeout to wait for image map status to be 'OK'
        interval (int): optional interval to query image status
        server_id (int): Server Id to be specified for S3260 platforms
    Raises:
        Exception if invalid protocol in URI
        Exception when the mapping doesn't reach 'OK' status
    Returns:
        True if mapping succeeded
    Examples:
        vmedia_mount_uri(
            handle,
            uri="http://1.1.1.1/files/ubuntu-14.04.2-server-amd64.iso"
        )
    """

    # Verify interval not set to zero
    if interval < 1 or type(interval) is not int:
        raise ValueError("ERROR: interval must be positive integer")

    # Parse file/path from URI
    remote_file = os.path.basename(uri)
    remote_share = os.path.dirname(uri) + "/"
    mount_options = "noauto"

    # Set the Map based on the protocol
    if urlsplit(uri).scheme == 'http':
        mount_protocol = "www"
    elif urlsplit(uri).scheme == 'https':
        mount_protocol = "www"
    elif CIFS_URI_PATTERN.match(uri):
        mount_protocol = "cifs"
    elif NFS_URI_PATTERN.match(uri):
        mount_protocol = "nfs"
    else:
        # Raise ValueError and bail
        raise ValueError("Unsupported protocol: " +
                         urlsplit(uri).scheme)

    # Use remote filename if no volume_name givien
    if not volume_name:
        volume_name = remote_file
    # Convert no user/pass to blank strings
    if not user_id:
        user_id = ''
    if not password:
        password = ''

    # Map the file
    vmedia_mount_create(handle,
                        volume_name=volume_name[:45],
                        map=mount_protocol,
                        mount_options=mount_options,
                        remote_share=remote_share,
                        remote_file=remote_file,
                        username=user_id,
                        password=password,
                        server_id=server_id)

    # Verify correct URL was mapped
    if uri in vmedia_get_existing_uri(handle, server_id):
        # Loop until mapping moves out of 'In Progress' state
        wait_time = 0
        status_list = vmedia_get_existing_status(handle, server_id)
        while 'In Progress' in status_list:
            # Raise error if we've reached timeout
            if wait_time > timeout:
                raise ImcOperationError(
                    'Mount Virtual Media',
                    '{0}: ERROR - Mapped image status stuck at [In Progress]'.format(handle.ip)
                )
            # Wait interval sec between checks
            time.sleep(interval)
            status_list = vmedia_get_existing_status(handle, server_id)
            wait_time += interval
        else:
            # Verify mapping transitioned to 'OK' state
            if 'OK' in status_list:
                return True
            else:
                raise ImcOperationError(
                    'Mount Virtual Media',
                    '{0}: ERROR - Mapped image status is {1}'.format(handle.ip, status_list)
                )
    else:
        raise ImcOperationError(
            'Mount Virtual Media',
            '{0}: ERROR - Image {1} did not get mapped.'.format(handle.ip, uri)
        )


def MountVmedia(handle, ip, fileuri, volume_name):
    log.info("Preparing to mount virtual media on <%s>.", ip)
    print "Preparing to mount virtual media on <"+ ip +">.\n"
    # First make sure we enable vMedia
    mo = CommVMedia(parent_mo_or_dn=_get_comm_mo_dn(handle, server_id=1))
    params = {
        "admin_state": "enabled",
        "encryption_state": "Disabled",
        "low_power_usb_state": "Disabled",
        "low_power_usb": "Disabled",
    }
    mo.set_prop_multiple(**params)
    handle.set_mo(mo)
    # Now mount the vMedia
    vmedia_mount_uri(
            handle,
            volume_name=volume_name,
            uri=fileuri
        )


def CheckBios(handle, ip):
    log = logging.getLogger()
    global bios_changed
    if bios_tokens_exist(handle,
                          tokens = {
                            "BaudRate": "115200",
                            "ConsoleRedirection": "com0",
                            "FlowControl": "None",
                            "TerminalType": "VT100"},
                          server_id=1):
        log.info("Great! The BIOS on <%s> already has all of the settings we need.", ip)
        print "Great! The BIOS on <"+ip+"> already has all of the settings we need.\n"
    else:
        log.warning("The BIOS settings will need to be changed on <%s> to support this script.", ip)
        print "The BIOS settings will need to be changed on <"+ip+"> to support this script.\n"
        bios_changed = True
        log.info("Backing up the current BIOS settings on <%s>.", ip)
        print "Backing up the current BIOS settings on <"+ip+">.\n"
        bios_profile_backup_running(handle)
        log.info("Setting new BIOS parameters on <%s> to support SOL.", ip)
        print "Setting new BIOS parameters on <"+ip+"> to support SOL.\n"
        SetBios(handle)
        log.info("The BIOS on <%s> has been updated. Changes will take effect when we reboot.", ip)
        print "The BIOS on <"+ip+"> has been updated. Changes will take effect when we reboot.\n"


def SetBios(handle):
    tokens = {
        "BaudRate": "115200",
        "ConsoleRedirection": "com-0",
        "FlowControl": "none",
        "TerminalType": "vt100"}
    server_id=1

    from imcsdk.imccoreutils import load_class

    parent_dn = _get_bios_dn(handle, server_id) + "/bios-settings"
    mo_table = _get_bios_mo_table(handle, tokens, server_id)

    for mo_name, props in mo_table.items():
        mo_class = load_class(mo_name)
        mo_obj = mo_class(parent_mo_or_dn=parent_dn, **props)
        handle.set_mo(mo_obj)


def sol_get(handle, server_id=1, caller="sol_get"):
    parent_dn = get_server_dn(handle, server_id)
    dn = parent_dn + "/sol-if"
    mo = handle.query_dn(dn)
    if mo is None:
        raise ImcOperationError(caller,
                                "SOL '%s' doesn't exist." % dn)
    return mo


def CheckSolStatus(handle, server_id=1, **kwargs):
    try:
        mo = sol_get(handle, server_id=server_id, caller="sol_enable")
    except ImcOperationError:
        return (False, None)

    kwargs['admin_state'] = SolIfConsts.ADMIN_STATE_ENABLE

    mo_exists = mo.check_prop_match(**kwargs)
    return (True if mo_exists else None)


def EnableSol(handle, server_id=1, **kwargs):
    """
    This method will setup serial over lan connection
    Args:
        handle (ImcHandle)
        speed (int): 9600, 19200, 38400, 57600, 115200
        comport (string): "com0", "com1"
        ssh_port (int): port for ssh
        server_id (int): Server Id to be specified for C3260 platforms
    Returns:
        SolIf object
    """

    mo = sol_get(handle, server_id=server_id, caller="sol_enable")
    params = {
        "admin_state": SolIfConsts.ADMIN_STATE_ENABLE,
        "speed": "115200",
        "comport": "com0",
        "ssh_port": "2400"
    }

    mo.set_prop_multiple(**kwargs)
    mo.set_prop_multiple(**params)
    handle.set_mo(mo)
    return mo


def RunBootUtil(ip, user, pwd):
    child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+user+'@'+ip)
    child.delaybeforesend = 2
    child.expect('assword:')
    child.sendline('Cisco12345')
    child.expect ('# ')
    child.sendline('connect host')
    child.sendline('\r\n')
    child.expect('Shell>', timeout=1500)
    child.sendline('FS0:')
    child.sendline('\r\n')
    child.expect('FS0:')
    child.sendline('cd BootUtil-v1.6.57.0-efi\\BootUtil-v1.6.57.0')
    child.send('\r\n')
    child.expect_exact('\BootUtil-v1.6.57.0\>')
    child.sendline('bootutil64e.efi -nic=1 -bootenable=pxe')
    child.send('\r\n')
    child.expect_exact('\BootUtil-v1.6.57.0\>')
    child.sendline('bootutil64e.efi -nic=2 -bootenable=pxe')
    child.send('\r\n')
    child.expect_exact('\BootUtil-v1.6.57.0\>')
    child.sendline('bootutil64e.efi -nic=3 -bootenable=pxe')
    child.send('\r\n')
    child.expect_exact('\BootUtil-v1.6.57.0\>')
    child.sendline('bootutil64e.efi -nic=4 -bootenable=pxe')
    child.send('\r\n')
    child.expect_exact('\BootUtil-v1.6.57.0\>')
    child.sendline('bootutil64e.efi -nic=5 -bootenable=pxe')
    child.send('\r\n')
    child.expect_exact('\BootUtil-v1.6.57.0\>')
    child.sendline('bootutil64e.efi -nic=6 -bootenable=pxe')
    child.send('\r\n')
    child.expect_exact('\BootUtil-v1.6.57.0\>')
    child.sendline('\x18')
    child.send('\r\n')
    child.expect('# ')
    child.sendline('scope bios')
    child.expect('# ')
    child.sendline('set boot-mode Legacy')
    child.expect('# ')
    child.sendline('set boot-order pxe,hdd,efi')
    child.expect('# ')
    child.sendline('commit')
    child.expect('# ')
    child.sendline('exit')


def DisableSol(handle, server_id=1):
    """
    This method will disable Serial over Lan connection
    Args:
        handle (ImcHandle)
        server_id (int): Server Id to be specified for C3260 platforms
    Returns:
        None
    """

    mo = sol_get(handle, server_id=server_id, caller="sol_enable")
    mo.admin_state = SolIfConsts.ADMIN_STATE_DISABLE
    handle.set_mo(mo)
    return mo


def vmedia_mount_remove_image(handle, image_type, server_id=1):
    """
    This method will remove the vmedia mapping of specific type
    Args:
        handle (ImcHandle)
        image_type (str): 'iso' or 'img'
        server_id (int): Server Id to be specified for C3260 platforms
    Raises:
        Exception if mapping is able to be removed
    Returns:
        True
    Examples:
        vmedia_mount_remove_image(handle, image_type='iso')
    """

    # Get all current virtually mapped ISOs
    virt_media_maps = handle.query_children(in_dn=_get_vmedia_mo_dn(handle,
                                                                    server_id))
    # Loop over each mapped ISO
    for virt_media in virt_media_maps:
        # Remove the mapped ISO
        virt_media_type = virt_media.remote_file.split('.')[-1]
        if virt_media_type == image_type:
            handle.remove_mo(virt_media)
            break


def UnmountVmedia(handle, volume_name):
    log = logging.getLogger()
    vmediamap_mo = CommVMediaMap(
        parent_mo_or_dn=_get_vmedia_mo_dn(handle, server_id=1),
        volume_name=volume_name)
    vmediamap_mo = handle.query_dn(dn=vmediamap_mo.dn)
    if vmediamap_mo is None:
        log.error("Volume '%s' does not exist on %s", volume_name, handle.ip)
        raise ValueError("Volume '%s' does not exist on %s" % (volume_name, handle.ip))

    handle.remove_mo(vmediamap_mo)


def _set_power_state(handle, server_dn, state):
    server_mo = handle.query_dn(server_dn)
    if handle.platform == IMC_PLATFORM.TYPE_CLASSIC:
        mo_class = ComputeRackUnitConsts
    elif handle.platform == IMC_PLATFORM.TYPE_MODULAR:
        mo_class = ComputeServerNodeConsts
    else:
        raise ImcOperationError("Set Power State", "Unknown platform:%s found" %
                                handle.platform)

    state_dict = {
        "up": mo_class.ADMIN_POWER_UP,
        "down": mo_class.ADMIN_POWER_DOWN,
        "graceful-down": mo_class.ADMIN_POWER_SOFT_SHUT_DOWN,
        "cycle": mo_class.ADMIN_POWER_CYCLE_IMMEDIATE
    }

    server_mo.admin_power = state_dict[state]
    handle.set_mo(server_mo)


def server_power_state_get(handle, server_id=1):
    """
    This method will return the oper power status of the rack server
    Args:
        handle (ImcHandle)
        server_id (int): Server Id to be specified for C3260 platforms
    Examples:
        For classic or non-C3260 series servers:-
        server_power_state_get(handle)
        For modular or C3260 series servers, server_id should also be passed
        in the params:-
        server_power_state_get(handle, server_id=1)
        If server_id is not specified, this will assume server_id="1"
    Returns:
        oper power state(string)
    """

    server_dn = get_server_dn(handle, server_id)
    server_mo = handle.query_dn(server_dn)
    if server_mo:
        return server_mo.oper_power

    raise ImcOperationError("Get Server Power State",
                            "Managed Object not found for dn:%s" % server_dn)


def _wait_for_power_state(handle, state, timeout=60, interval=5, server_id=1):
    log = logging.getLogger()
    """
    This method should be called after a power state change has been triggered.
    It will poll the server and return when the desired state is achieved.
    Args:
        handle(ImcHandle)
        state(str)
        timeout(int)
        interval(int)
        server_id (int): Server Id to be specified for C3260 platforms
    Returns:
        bool
    """
    # Verify desired state is valid
    if state not in ("on", "off"):
        raise ValueError("ERROR invalid state: {0}".format(state))

    # Verify interval not set to zero
    if interval < 1 or type(interval) is not int:
        raise ValueError("ERROR: interval must be positive integer")

    wait_time = 0
    while server_power_state_get(handle, server_id) != state:
        # Raise error if we've reached timeout
        if wait_time > timeout:
            log.error("Power State Change {%s}: Power {%s} did not complete within {%s} sec.", handle.ip, state, str(timeout) )
            raise ImcOperationError(
                'Power State Change',
                '{%s}: ERROR - Power {%s} did not complete within '
                '{%s} sec' % (handle.ip, state, timeout)
            )
        # Wait interval sec between checks
        time.sleep(interval)
        wait_time += interval


def RebootServer(handle, ip, timeout=120, interval=5, server_id=1, **kwargs):
    log = logging.getLogger()
    """
    This method will power cycle the rack server immediately.
    Args:
        handle(ImcHandle)
        server_id (int): Server Id to be specified for C3260 platforms
        kwargs: key=value paired arguments
    Returns:
        ComputeRackUnit object for non-C3260 platform
        ComputeServerNode object for C3260 platform
    Example:
        server_power_cycle(handle) for non-C3260 platforms
        server_power_cycle(handle, timeout=120, interval=10) 
                for non-C3260 platforms
        server_power_cycle(handle, server_id=2, timeout=60) for C3260 platforms
    """

    server_dn = get_server_dn(handle, server_id)
    _set_power_state(handle, server_dn, "cycle")

    # Poll until the server is powered up
    _wait_for_power_state(handle, "on", timeout=timeout,
                          interval=interval, server_id=server_id)
    log.info("Reboot complete on server %s", ip)

    return handle.query_dn(server_dn)

def Updater(thread_queue):
    # This is the main program for doing the updates, designed so that can be threaded
    log = logging.getLogger()
    inputs = []

    while True:
        try:
            inputs = thread_queue.get(True, 5)
            ip = inputs[0]
            user = inputs[1]
            password = inputs[2]

            log.info("Attempting login to IMC at <%s> for SOL access...", ip)
            print "\n\nAttempting login to IMC at <"+ ip +"> for SOL access...\n"
            handle=DoLogin(ip, user, password)

            MountVmedia(handle, ip, fileuri, volume_name)

            log.info("Ensuring BIOS settings are appropriate for SOL on <%s>.", ip)
            print "Ensuring BIOS settings are appropriate for SOL on <"+ ip +">.\n"
            CheckBios(handle, ip)

            log.info("Checking SOL status on  <%s>.", ip)
            print "Checking SOL status on  <"+ ip +">.\n"
            solstatus = CheckSolStatus(handle)
            if not solstatus:
                log.warning("The SOL is not enabled for <%s> so I am enabling it now. It will be disabled again when we are done.", ip)
                print "The SOL is not enabled for <"+ ip +"> so I am enabling it now. It will be disabled again when we are done.\n"
                EnableSol(handle)

            log.info("Power cycling <%s> for changes to take effect.", ip)
            print "Power cycling <"+ ip +"> for changes to take effect.\n"
            RebootServer(handle, ip)

            log.info("Attaching to SOL on <%s> and updating NIC firmware. This may take a while.", ip)
            print "Attaching to SOL on <"+ ip +"> and updating NIC firmware. This may take a while.\n"
            RunBootUtil(ip, user, password)
            
            log.info("Changes were successful on  <%s>. Unmounting Intel(R) BootUtil image.", ip)
            print "Changes were successful on  <"+ ip +">. Unmounting Intel(R) BootUtil image.\n"
            UnmountVmedia(handle, volume_name)

            if not solstatus:
                log.info("Disabling SOL on  <%s> since it was not previously enabled.", ip)
                print "Disabling SOL on  <"+ ip +"> since it was not previously enabled.\n"
                DisableSol(handle)

            if bios_changed and not biosuri:
                log.info("Reverting BIOS to previous settings and rebooting  < %s >.", ip)
                print "Reverting BIOS to previous settings and rebooting  <"+ ip +">.\n"
                bios_profile_activate(handle, name='cisco_backup_profile', backup_on_activate=False)
                RebootServer(handle, ip)

            if biosuri:
                log.info("Applying golden BIOS settings and rebooting  < %s >.", ip)
                print "Applying golden BIOS settings and rebooting  <"+ ip +">.\n"
                bios_profile_upload(handle, biosuri, user=biosuser, pwd=biospwd)
                bios_profile_activate(handle, biosname, backup_on_activate=False, reboot_on_activate=False)
                RebootServer(handle, ip)
            
            log.info("Work complete on  <%s>. Logging out...", ip)
            print "Work complete on  <"+ ip +">. Logging out...\n"
            DoLogout(handle)
            thread_queue.task_done()

        except Exception, err:
                if handleList:
                    DoLogout(handle)
                log.exception("General Exception: %s", str(err) )
                print "General Exception:", str(err)
                log.exception("General Exception: Unable to upgrade firmware on <%s>. Please check the log.", ip )
                print "General Exception: Unable to upgrade firmware on <"+ip+">. Please check the log."
                thread_queue.task_done()
                break


if __name__ == '__main__':
    global fileuri
    global biosuri
    biosuri = ""
    global biosname
    biosname = ""
    global biosuser
    biosuser = ""
    global biospwd
    biospwd = ""
    my_queue = Queue()
    my_threads = []
    try:
        ft = logging.Formatter(fmt=("%(asctime)s:%(msecs)d|%(threadName)s|%(message)s"),
                       datefmt="%Y-%m-%d %H:%M:%S")
        ch = logging.StreamHandler()
        ch.setFormatter(ft)
        log = logging.getLogger()
        log.addHandler(ch)

        CheckHostOS()

        parser = optparse.OptionParser()
        parser.add_option('-i', '--ip',dest="ip",
                          help="[Required] IMC IP Address, if -f option not used")
        parser.add_option('-u', '--username',dest="userName",
                          help="[Optional] Account Username for IMC Login, if -f option not used")
        parser.add_option('-p', '--password',dest="password",
                          help="[Optional] Account Password for IMC Login")
        parser.add_option('-f', '--filename',dest="fileName",
                          help="[Optional] Path to local CSV file of IP, user, password for multiple IMCs")

        (options, args) = parser.parse_args()

        fileuri = str(raw_input("Please enter the URI for the Intel(R) BootUtil IMG file (e.g. http://ip/file.img): "))
        log.info("The URI for the BootUtil .img file is %s",fileuri)

        getgoldbios = QueryYesNo("Would you like to use a master BIOS file to standardize BIOS settings? ", None)
        if getgoldbios:
            biosuri = str(raw_input("Please enter the URI for the CIMC BIOS import file (e.g. http://ip/file.json): "))
            log.info("The URI for the golden BIOS file is %s",biosuri)
            while biosname == "":
                biosname = str(raw_input("Please enter the name of the BIOS profile as it appers in the JSON file: "))
            biosuser = str(raw_input("Please enter the username, if any, for accessing the BIOS import file: "))
            if biosuser:
                biospwd = str(raw_input("Please enter the password, if any, for accessing the BIOS import file:  "))

        if not options.fileName:

            if not options.ip:
                parser.print_help()
                parser.error("\nPlease provide a IMC IP, username, and password as input.\n")

            if not IsValidIpv4(options.ip):
                parser.print_help()
                parser.error("\nThat IMC address is invalid. Please enter a valid IPv4 address.\n")

            if not PingTest(options.ip):
                parser.print_help()
                parser.error("\nThis IMC does not appear online. Please enter a valid IPv4 address.\n")

            if not options.userName:
                parser.error("\nPlease provide IMC UserName\n")
                parser.print_help()

            else:

                if not options.password:
                    options.password=GetPassword("IMC Password:")
            
            #Updater(options.ip,options.userName,options.password,fileuri)
            curr_thread = threading.Thread(target=Updater,
                                            args=(my_queue,))
            curr_thread.start()
            my_threads.append(curr_thread)
            my_queue.put([options.ip,options.userName,options.password])

        elif options.fileName:
            with open(options.fileName, 'rb') as csvfile:
                imclist = list(csv.reader(csvfile))
            num_imc = len(imclist)
            print "\nYour file contains "+str(num_imc)+" records.\n"
            numthreads = int(raw_input("Please enter the number of devices you want to upgrade at a time. We recommend no more than 10: "))
            if {numthreads > num_imc}:
                numthreads = num_imc

            for val in range(numthreads):
                curr_thread = threading.Thread(target=Updater,
                                            args=(my_queue,))
                curr_thread.start()
                my_threads.append(curr_thread)

            for lines in range(num_imc):
                my_queue.put(imclist[lines])

        else:
            parser.print_help()
            parser.error("\nYou must enter at least one option.\n")

    except Exception, err:
        print "General Exception:", str(err)