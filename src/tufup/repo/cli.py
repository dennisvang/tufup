import argparse
import json
import logging

import packaging.version
from tuf.api.metadata import TOP_LEVEL_ROLE_NAMES

from tufup.utils import log_print, input_bool, input_numeric, input_text, input_list
from tufup.repo import Repository

logger = logging.getLogger(__name__)

HELP = dict(
    version='show version and exit',
    common_key_dirs='Directories to search for private and/or public keys.',
    targets_add=(
        'Add app bundle to the repository. Creates archive and patch from'
        ' bundle files.'
    ),
    targets_add_app_version='Application version (PEP440 compliant)',
    targets_add_bundle_dir='Directory containing application bundle.',
    targets_add_skip_patch='Skip patch creation.',
    targets_add_required='Mark release as "required".',
    targets_add_meta='Specify custom metadata as a JSON object.',
    targets_remove_latest='Remove latest app bundle from the repository.',
    keys_subcommands='Optional commands to add or replace keys.',
    keys_new_key_name='Name of new private key (public key gets .pub suffix).',
    keys_role_name='Register public key for this role.',
    keys_encrypted='New private key is (to be) encrypted.',
    keys_create='Create a new key pair (private & public).',
    keys_old_key_name='Revoke old public key, replace by new public key.',
    sign_role_name='Name of role to be signed.',
    sign_expiration_days=(
        'Set expiration date as number of days from today. Metadata version '
        'and expiration date for dependent roles will also be updated.'
    ),
)


def json_object(arg: str) -> dict:
    """decodes a JSON object"""
    value = json.loads(arg)
    if not isinstance(value, dict):
        # arg must represent a JSON object, which corresponds with a python dict
        raise ValueError
    return value


def _print_info(message: str):
    return log_print(message=message, level=logging.INFO, logger=logger)


def _get_repo():
    try:
        return Repository.from_config()
    except TypeError:
        _print_info('Failed to load config. Did you initialize the repository?')


def _add_key_dirs_argument(parser: argparse.ArgumentParser):
    parser.add_argument('key_dirs', nargs='+', help=HELP['common_key_dirs'])


def get_parser() -> argparse.ArgumentParser:
    # https://docs.python.org/3/library/argparse.html#sub-commands
    # https://docs.python.org/3/library/argparse.html#parents
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-v', '--version', action='store_true', required=False, help=HELP['version']
    )
    subparsers = parser.add_subparsers()
    # add debug option
    debug_parser = argparse.ArgumentParser(add_help=False)
    debug_parser.add_argument('-d', '--debug', action='store_true', required=False)
    # init
    subparser_init = subparsers.add_parser('init', parents=[debug_parser])
    subparser_init.set_defaults(func=_cmd_init)
    # targets
    subparser_targets = subparsers.add_parser('targets', parents=[debug_parser])
    subparser_targets.set_defaults(func=_cmd_targets)
    # we use nested subparsers to deal with mutually dependent arguments
    targets_subparsers = subparser_targets.add_subparsers(
        dest='subcommand', required=True
    )
    subparser_targets_add = targets_subparsers.add_parser(
        'add', help=HELP['targets_add']
    )
    subparser_targets_add.add_argument(
        'app_version',
        action=_StoreVersionAction,
        help=HELP['targets_add_app_version'],
    )
    subparser_targets_add.add_argument(
        'bundle_dir', help=HELP['targets_add_bundle_dir']
    )
    subparser_targets_add.add_argument(
        '-s',
        '--skip-patch',
        action='store_true',
        required=False,
        help=HELP['targets_add_skip_patch'],
    )
    subparser_targets_add.add_argument(
        '-r',
        '--required',
        action='store_true',
        required=False,
        help=HELP['targets_add_required'],
    )
    subparser_targets_add.add_argument(
        '-m',
        '--meta',
        action='store',
        type=json_object,
        required=False,
        help=HELP['targets_add_meta'],
    )
    subparser_targets_remove = targets_subparsers.add_parser(
        'remove-latest', help=HELP['targets_remove_latest']
    )
    for sp in [subparser_targets_add, subparser_targets_remove]:
        _add_key_dirs_argument(parser=sp)
    # keys
    subparser_keys = subparsers.add_parser('keys', parents=[debug_parser])
    subparser_keys.set_defaults(func=_cmd_keys)
    subparser_keys.add_argument('new_key_name', help=HELP['keys_new_key_name'])
    subparser_keys.add_argument(
        '-c', '--create', action='store_true', help=HELP['keys_create']
    )
    subparser_keys.add_argument(
        '-e', '--encrypted', action='store_true', help=HELP['keys_encrypted']
    )
    # we use nested subparsers to deal with mutually dependent arguments
    keys_subparsers = subparser_keys.add_subparsers(
        dest='subcommand', help=HELP['keys_subcommands']
    )
    subparser_keys_add = keys_subparsers.add_parser('add')
    subparser_keys_add.add_argument(
        'role_name', choices=TOP_LEVEL_ROLE_NAMES, help=HELP['keys_role_name']
    )
    subparser_keys_replace = keys_subparsers.add_parser('replace')
    subparser_keys_replace.add_argument('old_key_name', help=HELP['keys_old_key_name'])
    for sp in [subparser_keys_add, subparser_keys_replace]:
        _add_key_dirs_argument(parser=sp)
    # sign
    subparser_sign = subparsers.add_parser('sign', parents=[debug_parser])
    subparser_sign.set_defaults(func=_cmd_sign)
    subparser_sign.add_argument(
        'role_name', choices=TOP_LEVEL_ROLE_NAMES, help=HELP['sign_role_name']
    )
    subparser_sign.add_argument(
        '-e',
        '--expiration-days',
        required=False,
        nargs='?',
        const='default',  # if option -e is specified without value
        default=None,  # if option -e is not specified at all
        help=HELP['sign_expiration_days'],
    )
    _add_key_dirs_argument(parser=subparser_sign)
    return parser


class _StoreVersionAction(argparse.Action):
    """Validates version string before storing."""

    def __call__(self, parser, namespace, values, option_string=None, **kwargs):
        # The first value should comply with PEP440
        value = values[0]
        try:
            packaging.version.Version(value)
        except packaging.version.InvalidVersion:
            raise argparse.ArgumentError(
                self,
                f'Version string "{value}" is not PEP440 compliant.\n '
                f'See examples: https://www.python.org/dev/peps/pep-0440/\n',
            )
        # Store the value, same as "store" action
        setattr(namespace, self.dest, values)


def _get_config_from_user(**kwargs) -> dict:
    top_level_role_names = ['root', 'targets', 'snapshot', 'timestamp']
    for key, example, optional in [
        ('app_name', '', False),
        ('app_version_attr', ', e.g. my_app.__version__', True),
        ('repo_dir', '', False),
        ('keys_dir', '', False),
    ]:
        kwargs[key] = input_text(
            prompt=f'Specify {key}{example}',
            default=kwargs.get(key),
            optional=optional,
        )
    key_map = kwargs.get('key_map', {})
    expiration_days = kwargs.get('expiration_days', {})
    thresholds = kwargs.get('thresholds', {})
    encrypted_keys = kwargs.get('encrypted_keys', [])
    new_encrypted_keys = []
    unique_key_names = []
    for role_name in top_level_role_names:
        # key_map
        key_names = []
        while not key_names:
            key_names = input_list(
                prompt=f'Specify key names for {role_name}',
                default=key_map.get(role_name, [role_name]),
            )
        key_map[role_name] = key_names
        # encrypted_keys
        for key_name in key_names:
            if key_name not in unique_key_names:
                unique_key_names.append(key_name)
                if input_bool(
                    prompt=f'Encrypt key "{key_name}"?',
                    default=key_name in encrypted_keys,
                ):
                    new_encrypted_keys.append(key_name)
        # expiration_days
        expiration_days[role_name] = input_numeric(
            prompt=f'Specify number of days before {role_name} expires',
            default=expiration_days.get(role_name, 1),
        )
        # thresholds
        thresholds[role_name] = input_numeric(
            prompt=f'Specify required number of signatures for {role_name}',
            default=thresholds.get(role_name, 1),
        )
    kwargs['key_map'] = key_map
    kwargs['expiration_days'] = expiration_days
    kwargs['encrypted_keys'] = new_encrypted_keys
    kwargs['thresholds'] = thresholds
    return kwargs


def _cmd_init(options: argparse.Namespace):
    logger.debug(f'command init: {vars(options)}')
    # try to load existing config
    config_dict = Repository.load_config()
    modify = True
    message = 'Creating new configuration.'
    if config_dict:
        modify = input_bool(
            prompt='Found existing configuration. Modify?', default=False
        )
        if modify:
            message = 'Modifying existing configuration.'
        else:
            message = 'Using existing configuration.'
    _print_info(message)
    if modify:
        config_dict = _get_config_from_user(**config_dict)
    # create repository instance
    repository = Repository(**config_dict)
    # save new or updated configuration
    _print_info('Saving config...')
    repository.save_config()
    # create directories, keys, and root metadata file
    _print_info('Initializing repository...')
    repository.initialize()
    _print_info('Done.')


def _cmd_keys(options: argparse.Namespace):
    logger.debug(f'command keys: {vars(options)}')
    repository = _get_repo()
    public_key_path = repository.keys.public_key_path(key_name=options.new_key_name)
    private_key_path = repository.keys.private_key_path(key_name=options.new_key_name)
    if options.create:
        _print_info(f'Creating key pair for {options.new_key_name}...')
        repository.keys.create_key_pair(
            private_key_path=private_key_path, encrypted=options.encrypted
        )
        _print_info('Key pair created.')
    if options.subcommand == 'replace':
        _print_info(
            f'Replacing key {options.old_key_name} by {options.new_key_name}...'
        )
        repository.replace_key(
            old_key_name=options.old_key_name,
            new_public_key_path=public_key_path,
            new_private_key_encrypted=options.encrypted,
        )
    elif options.subcommand == 'add':
        _print_info(f'Adding key {options.new_key_name}...')
        repository.add_key(
            role_name=options.role_name,
            public_key_path=public_key_path,
            encrypted=options.encrypted,
        )
    if options.subcommand in ['add', 'replace']:
        _print_info('Publishing changes...')
        repository.publish_changes(private_key_dirs=options.key_dirs)
    _print_info('Done.')


def _cmd_targets(options: argparse.Namespace):
    logger.debug(f'command targets: {vars(options)}')
    repository = _get_repo()
    if options.subcommand == 'add':
        _print_info('Adding bundle...')
        repository.add_bundle(
            new_version=options.app_version,
            new_bundle_dir=options.bundle_dir,
            skip_patch=options.skip_patch,
            required=options.required,
            custom_metadata=options.meta,
        )
    elif options.subcommand == 'remove-latest':
        _print_info('Removing latest bundle...')
        repository.remove_latest_bundle()
    _print_info('Publishing changes...')
    repository.publish_changes(private_key_dirs=options.key_dirs)
    _print_info('Done.')


def _cmd_sign(options: argparse.Namespace):
    logger.debug(f'command sign: {vars(options)}')
    repository = _get_repo()
    if options.expiration_days is not None:
        # default or custom
        days = repository.expiration_days.get(options.role_name)
        if options.expiration_days.isnumeric():
            days = int(options.expiration_days)
        # change expiration date in signed metadata
        _print_info(f'Setting expiration date {days} days from now...')
        repository.refresh_expiration_date(role_name=options.role_name, days=days)
        # also update version and expiration date for dependent roles, and sign
        # modified roles
        _print_info('Publishing changes...')
        repository.publish_changes(private_key_dirs=options.key_dirs)
    else:
        # sign without changing the signed metadata (for threshold signing)
        _print_info('Adding signature...')
        repository.threshold_sign(
            role_name=options.role_name,
            private_key_dirs=options.key_dirs,
        )
    _print_info('Done.')
