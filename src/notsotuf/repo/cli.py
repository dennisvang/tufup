import argparse
import logging

import packaging.version

from notsotuf.utils import input_bool, input_numeric, input_text, input_list
from notsotuf.repo import Repository

logger = logging.getLogger(__name__)


def get_parser() -> argparse.ArgumentParser:
    # https://docs.python.org/3/library/argparse.html#sub-commands
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    # init
    subparser_init = subparsers.add_parser('init')
    subparser_init.set_defaults(func=_cmd_init)
    # targets
    subparser_targets = subparsers.add_parser('targets')
    subparser_targets.set_defaults(func=_cmd_targets)
    subparser_targets.add_argument(
        '-a',
        '--add',
        metavar=('<version>', '<bundle directory>'),
        action=_StoreVersionAction,
        nargs=2,
        help=HELP['targets_add'],
    )
    subparser_targets.add_argument(
        '-r', '--remove', action='store_true', help=HELP['targets_remove']
    )
    # keys
    subparser_keys = subparsers.add_parser('keys')
    subparser_keys.set_defaults(func=_cmd_keys)
    subparser_keys.add_argument('-c', '--create', help=HELP['keys_create'])
    subparser_keys.add_argument('-a', '--add', help=HELP['keys_add'])
    subparser_keys.add_argument('-r', '--revoke', help=HELP['keys_revoke'])
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
    # todo
    logger.debug(f'command keys: {vars(options)}')
    if options.create:
        pass
    elif options.add:
        pass
    elif options.revoke:
        pass


def _cmd_targets(options: argparse.Namespace):
    logger.debug(f'command targets: {vars(options)}')
    try:
        repository = Repository.from_config()
    except TypeError:
        print('Failed to load configuration. Did you initialize the repository?')
        return
    if options.add:
        logger.debug('attempting to add bundle')
        repository.add_bundle(
            new_version=options.add[0], new_bundle_dir=options.add[1]
        )
    elif options.remove:
        logger.debug('attempting to remove latest bundle')
        repository.remove_latest_bundle()


HELP = dict(
    targets_add=(
        'Add specified app bundle to the repository. Creates archive and '
        'patch from bundle files. '
    ),
    targets_remove='Remove latest app bundle from the repository.',
    keys_create='Create a new key pair and add it to the repository.',
    keys_add='Add an existing key to the repository.',
    keys_revoke='Revoke a repository key.',
)
