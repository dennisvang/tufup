import argparse
import logging
import sys

import packaging.version

from notsotuf.repo import Repository
from notsotuf.utils import get_config_from_user, input_bool

# https://packaging.python.org/en/latest/guides/single-sourcing-package-version/
__version__ = 2022.0

logger = logging.getLogger(__name__)


def main(args=None):
    print(f'notsotuf version: {__version__}')
    # default to --help
    if args is None:
        args = sys.argv[1:] or ['--help']

    # parse command line arguments
    parser = _get_parser()
    options = parser.parse_args(args=args)

    # process command
    try:
        options.func(options)
    except Exception:  # noqa
        logger.exception(f'Failed to process command: {args}')


class _StoreVersionAction(argparse.Action):
    """Validates version string before storing."""
    def __call__(self, parser, namespace, values, option_string=None, **kwargs):
        # The first value should comply with PEP440
        value = values[0]
        try:
            packaging.version.Version(value)
        except packaging.version.InvalidVersion:
            raise argparse.ArgumentError(self, MSG['not_pep440'].format(value))
        # Store the value, same as "store" action
        setattr(namespace, self.dest, values)


def _get_parser() -> argparse.ArgumentParser:
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
        '-a', '--add', action=_StoreVersionAction, nargs=2, help=MSG['targets_add']
    )
    subparser_targets.add_argument(
        '-r', '--remove', action='store_true', help=MSG['targets_remove']
    )
    # keys
    subparser_keys = subparsers.add_parser('keys')
    subparser_keys.set_defaults(func=_cmd_keys)
    subparser_keys.add_argument('-c', '--create')
    subparser_keys.add_argument('-a', '--add')
    subparser_keys.add_argument('-r', '--revoke')
    return parser


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
        config_dict = get_config_from_user(**config_dict)
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


MSG = dict(
    not_pep440=(
        'Version string "{}" is not PEP440 compliant.\n'
        'For examples, see https://www.python.org/dev/peps/pep-0440/.\n'
    ),
    targets_add=(
        'Add specified app bundle to the repository.\n'
        'Creates archive and patch from bundle files.\n'
        'Positional arguments:\n'
        '\tversion (PEP 440 compliant)\n'
        '\tpath to app bundle directory (relative or absolute)\n'
    ),
    targets_remove=(
        'Remove latest app bundle from the repository.\n'
        'Positional arguments: none\n'
    )
)


if __name__ == '__main__':
    main()
