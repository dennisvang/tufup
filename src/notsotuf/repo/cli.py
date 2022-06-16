import argparse
import logging

import packaging.version

from notsotuf.utils import input_bool, input_numeric, input_text, input_list
from notsotuf.repo import Repository

logger = logging.getLogger(__name__)

HELP = dict(
    common_key_dirs='Directories containing private and/or public keys.',
    targets_add=(
        'Add specified app bundle to the repository. Creates archive and '
        'patch from bundle files. '
    ),
    targets_remove='Remove latest app bundle from the repository.',
    keys_name='Name of private key (public key gets .pub suffix).',
    keys_role_name='Register public key for this role.',
    keys_encrypted='Private key is (to be) encrypted.',
    keys_create='Create a new key pair (private & public).',
    keys_old_key_id='Revoke old key id, replace by new public key.',
    sign_role_name='Name of role to be signed.',
    sign_expiration_days=(
        'Set expiration date as number of days from today. Metadata version '
        'and expiration date for dependent roles will also be updated.'
    ),
)


def _get_repo():
    try:
        return Repository.from_config()
    except TypeError:
        print('Failed to load config. Did you initialize the repository?')


def get_parser() -> argparse.ArgumentParser:
    # https://docs.python.org/3/library/argparse.html#sub-commands
    # https://docs.python.org/3/library/argparse.html#parents
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    # parent parser with common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        '-k',
        '--key-dirs',
        required=False,
        nargs='*',
        help=HELP['common_key_dirs'],
    )
    # init
    subparser_init = subparsers.add_parser('init')
    subparser_init.set_defaults(func=_cmd_init)
    # targets
    subparser_targets = subparsers.add_parser('targets', parents=[common_parser])
    subparser_targets.set_defaults(func=_cmd_targets)
    subparser_targets.add_argument(
        '-a',
        '--add',
        nargs=2,
        metavar=('<version>', '<bundle directory>'),
        action=_StoreVersionAction,
        help=HELP['targets_add'],
    )
    subparser_targets.add_argument(
        '-r', '--remove', action='store_true', help=HELP['targets_remove']
    )
    # keys
    subparser_keys = subparsers.add_parser('keys', parents=[common_parser])
    subparser_keys.set_defaults(func=_cmd_keys)
    subparser_keys.add_argument(
        '-n', '--key-name', required=True, help=HELP['keys_name']
    )
    subparser_keys.add_argument(
        '-r',
        '--role-name',
        required=False,
        choices=('root', 'targets', 'snapshot', 'timestamp'),
        help=HELP['keys_role_name'],
    )
    subparser_keys.add_argument(
        '-e', '--encrypted', action='store_true', help=HELP['keys_encrypted']
    )
    subparser_keys.add_argument(
        '-c', '--create', action='store_true', help=HELP['keys_create']
    )
    subparser_keys.add_argument(
        '-o', '--old-key-id', help=HELP['keys_old_key_id']
    )
    # sign
    subparser_sign = subparsers.add_parser('sign', parents=[common_parser])
    subparser_sign.set_defaults(func=_cmd_sign)
    subparser_sign.add_argument(
        '-r',
        '--role-name',
        required=True,
        choices=('root', 'targets', 'snapshot', 'timestamp'),
        help=HELP['sign_role_name'],
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
                f'See examples: https://www.python.org/dev/peps/pep-0440/\n'
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
    encrypted_keys = []
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
                        default=key_name in kwargs.get('encrypted_keys', [])
                ):
                    encrypted_keys.append(key_name)
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
    kwargs['encrypted_keys'] = encrypted_keys
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
    print(message)
    if modify:
        config_dict = _get_config_from_user(**config_dict)
    # create repository instance
    repository = Repository(**config_dict)
    # save new or updated configuration
    repository.save_config()
    print('Config saved.')
    # create directories, keys, and root metadata file
    repository.initialize()
    print('Repository initialized.')


def _cmd_keys(options: argparse.Namespace):
    logger.debug(f'command keys: {vars(options)}')
    repository = _get_repo()
    public_key_path = repository.keys.public_key_path(key_name=options.key_name)
    private_key_path = repository.keys.private_key_path(key_name=options.key_name)
    if options.create:
        repository.keys.create_key_pair(
            private_key_path=private_key_path, encrypted=options.encrypted
        )
    if options.old_key_id:
        repository.replace_key(
            old_key_id=options.old_key_id,
            new_public_key_path=public_key_path,
        )
    elif options.role_name:
        repository.roles.add_public_key(
            role_name=options.role_name, public_key_path=public_key_path
        )
    repository.publish_changes(private_key_dirs=options.key_dirs)


def _cmd_targets(options: argparse.Namespace):
    logger.debug(f'command targets: {vars(options)}')
    repository = _get_repo()
    if options.add:
        logger.debug('attempting to add bundle...')
        repository.add_bundle(
            new_version=options.add[0], new_bundle_dir=options.add[1]
        )
        logger.debug('done')
    elif options.remove:
        logger.debug('attempting to remove latest bundle...')
        repository.remove_latest_bundle()
        logger.debug('done')
    logger.debug('attempting to publish changes...')
    repository.publish_changes(private_key_dirs=options.private_key_dirs)
    logger.debug('done')


def _cmd_sign(options: argparse.Namespace):
    logger.debug(f'command sign: {vars(options)}')
    repository = _get_repo()
    if options.expiration_days:
        # default or custom
        days = repository.expiration_days.get(options.role_name)
        if options.expiration_days.isnumeric():
            days = int(options.expiration_days)
        # change expiration date in signed metadata
        repository.refresh_expiration_date(
            role_name=options.role_name, days=days
        )
        # also update version and expiration date for dependent roles, and sign
        # modified roles
        repository.publish_changes(private_key_dirs=options.private_key_dirs)
    else:
        # sign without changing the signed metadata (for threshold signing)
        repository.threshold_sign(
            role_name=options.role_name,
            private_key_dirs=options.private_key_dirs,
        )
