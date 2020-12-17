#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Stanislas Lange (angristan) <angristan@pm.me>
# Copyright: (c) 2018, Victor Carceler <vcarceler@iespuigcastellar.xeill.net>

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: snap

short_description: Manages snaps


description:
    - "Manages snaps packages."

options:
    name:
        description:
            - Name of the snap to install or remove. Can be a list of snaps.
        required: true
        type: list
        elements: str
    state:
        description:
            - Desired state of the package.
        required: false
        default: present
        choices: [ absent, present ]
        type: str
    classic:
        description:
            - Confinement policy. The classic confinement allows a snap to have
              the same level of access to the system as "classic" packages,
              like those managed by APT. This option corresponds to the --classic argument.
              This option can only be specified if there is a single snap in the task.
        type: bool
        required: false
        default: no
    channel:
        description:
            - Define which release of a snap is installed and tracked for updates.
              This option can only be specified if there is a single snap in the task.
        type: str
        required: false
        default: stable
    package_url:
        description:
            - Install snap package from a given url. THe package.assert file has to be
              at the same location as the specified package.snap file. Only the extension
              must be different.
              This option can only be specified if there is a single snap in the task.
        type: str
        required: false

author:
    - Victor Carceler (@vcarceler) <vcarceler@iespuigcastellar.xeill.net>
    - Stanislas Lange (@angristan) <angristan@pm.me>
'''

EXAMPLES = '''
# Install "foo" and "bar" snap
- name: Install foo
  community.general.snap:
    name:
      - foo
      - bar

# Remove "foo" snap
- name: Remove foo
  community.general.snap:
    name: foo
    state: absent

# Install a snap with classic confinement
- name: Install "foo" with option --classic
  community.general.snap:
    name: foo
    classic: yes

# Install a snap with from a specific channel
- name: Install "foo" with option --channel=latest/edge
  community.general.snap:
    name: foo
    channel: latest/edge

# Install a snap from a given url
  - name: Install foo from url
    community.general.snap:
      name: foo
      state: present
      classic: yes
      package_url: "{{ foo_package_url }}"
'''

RETURN = '''
classic:
    description: Whether or not the snaps were installed with the classic confinement
    type: bool
    returned: When snaps are installed
channel:
    description: The channel the snaps were installed from
    type: str
    returned: When snaps are installed
cmd:
    description: The command that was executed on the host
    type: str
    returned: When changed is true
snaps_installed:
    description: The list of actually installed snaps
    type: list
    returned: When any snaps have been installed
snaps_removed:
    description: The list of actually removed snaps
    type: list
    returned: When any snaps have been removed
'''

import operator
import re
import requests
import os

from ansible.module_utils.basic import AnsibleModule

DOWNLOAD_DIR = os.environ.get('HOME', '/tmp')

def is_downloadable(url):
    """
    Does the url contain a downloadable resource
    """
    h = requests.head(url, allow_redirects=True)
    header = h.headers
    content_type = header.get('content-type')
    if 'text' in content_type.lower():
        return False
    if 'html' in content_type.lower():
        return False
    return True

def validate_url(url):
    if not is_downloadable(url):
        module.fail_json(msg="Url '%s' is not downloadable." % url )

def download_file(url):
    filename = re.sub(r'^.*\/(.*)',r'\1',url)

    r = requests.get(url, allow_redirects=True)

    with open(DOWNLOAD_DIR + '/' + filename, 'wb') as f:
        f.write(r.content)

def ack_assert_file(module, local_assert_file):
    snap_path = module.get_bin_path("snap", True)
    cmd_parts = [snap_path, 'ack', local_assert_file]
    cmd = ' '.join(cmd_parts)
    rc, out, err = module.run_command(cmd, check_rc=True)

def validate_and_download_files(module):
    snap_file_url = module.params['package_url']
    assert_file_url = re.sub(r'^(.*)\.snap$',r'\1.assert', snap_file_url)
    local_base_filename = re.sub(r'^.*\/(.*)\.snap$',r'\1', snap_file_url)
    urls = [ snap_file_url, assert_file_url ]

    for url in urls:
        validate_url(url)
        download_file(url)

    return DOWNLOAD_DIR + '/' + local_base_filename

def validate_input_snaps(module):
    """Ensure that all exist."""
    for snap_name in module.params['name']:
        if not snap_exists(module, snap_name):
            module.fail_json(msg="No snap matching '%s' available." % snap_name)


def snap_exists(module, snap_name):
    snap_path = module.get_bin_path("snap", True)
    cmd_parts = [snap_path, 'info', snap_name]
    cmd = ' '.join(cmd_parts)
    rc, out, err = module.run_command(cmd, check_rc=False)

    return rc == 0


def is_snap_installed(module, snap_name):
    snap_path = module.get_bin_path("snap", True)
    cmd_parts = [snap_path, 'list', snap_name]
    cmd = ' '.join(cmd_parts)
    rc, out, err = module.run_command(cmd, check_rc=False)

    return rc == 0


def get_snap_for_action(module):
    """Construct a list of snaps to use for current action."""
    snaps = module.params['name']

    is_present_state = module.params['state'] == 'present'
    negation_predicate = operator.not_ if is_present_state else bool

    def predicate(s):
        return negation_predicate(is_snap_installed(module, s))

    return [s for s in snaps if predicate(s)]


def get_base_cmd_parts(module):
    action_map = {
        'present': 'install',
        'absent': 'remove',
    }

    state = module.params['state']

    classic = ['--classic'] if module.params['classic'] else []
    channel = ['--channel', module.params['channel']] if module.params['channel'] and module.params['channel'] != 'stable' else []

    snap_path = module.get_bin_path("snap", True)
    snap_action = action_map[state]

    cmd_parts = [snap_path, snap_action]
    if snap_action == 'install':
        cmd_parts += classic + channel

    return cmd_parts


def get_cmd_parts(module, snap_names):
    """Return list of cmds to run in exec format."""
    is_install_mode = module.params['state'] == 'present'
    has_multiple_snaps = len(snap_names) > 1

    cmd_parts = get_base_cmd_parts(module)
    has_one_pkg_params = '--classic' in cmd_parts or '--channel' in cmd_parts or module.params['package_url']

    if not (is_install_mode and has_one_pkg_params and has_multiple_snaps):
        return [cmd_parts + snap_names]

    return [cmd_parts + [s] for s in snap_names]


def run_cmd_for(module, snap_names):
    cmds_parts = get_cmd_parts(module, snap_names)
    cmd = '; '.join(' '.join(c) for c in cmds_parts)
    cmd = 'sh -c "{0}"'.format(cmd)

    # Actually execute the snap command
    return (cmd, ) + module.run_command(cmd, check_rc=False)


def execute_action(module, local_file = ''):
    is_install_mode = module.params['state'] == 'present'
    exit_kwargs = {
        'classic': module.params['classic'],
        'channel': module.params['channel'],
    } if is_install_mode else {}

    actionable_snaps = get_snap_for_action(module)
    if not actionable_snaps:
        module.exit_json(changed=False, **exit_kwargs)

    changed_def_args = {
        'changed': True,
        'snaps_{result}'.
        format(result='installed' if is_install_mode
               else 'removed'): actionable_snaps,
    }

    if module.check_mode:
        module.exit_json(**dict(changed_def_args, **exit_kwargs))

    if local_file:
        cmd, rc, out, err = run_cmd_for(module, [local_file])
    else:
        cmd, rc, out, err = run_cmd_for(module, actionable_snaps)

    cmd_out_args = {
        'cmd': cmd,
        'rc': rc,
        'stdout': out,
        'stderr': err,
    }

    if rc == 0:
        module.exit_json(**dict(changed_def_args, **dict(cmd_out_args, **exit_kwargs)))
    else:
        msg = "Ooops! Snap installation failed while executing '{cmd}', please examine logs and error output for more details.".format(cmd=cmd)
        if is_install_mode:
            m = re.match(r'^error: This revision of snap "(?P<package_name>\w+)" was published using classic confinement', err)
            if m is not None:
                err_pkg = m.group('package_name')
                msg = "Couldn't install {name} because it requires classic confinement".format(name=err_pkg)
        module.fail_json(msg=msg, **dict(cmd_out_args, **exit_kwargs))


def main():
    module_args = {
        'name': dict(type='list', elements='str', required=True),
        'state': dict(type='str', required=False, default='present', choices=['absent', 'present']),
        'classic': dict(type='bool', required=False, default=False),
        'channel': dict(type='str', required=False, default='stable'),
        'package_url': dict(type='str', required=False, default='')
    }
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        mutually_exclusive=[
          ('package_url', 'channel')
        ]
    )


    if module.params['package_url']:
        local_file = validate_and_download_files(module)
        ack_assert_file(module, local_file + '.assert')
        # Install local snap
        execute_action(module, local_file + '.snap')
    else:
        validate_input_snaps(module)
        # Apply changes to the snaps
        execute_action(module)


if __name__ == '__main__':
    main()
