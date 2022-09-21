import logging
import sys

from tufup.repo import cli
from tufup.utils import input_bool

# https://packaging.python.org/en/latest/guides/single-sourcing-package-version/
# https://semver.org/
__version__ = '0.4.1'

logger = logging.getLogger(__name__)


def main(args=None):
    print(f'tufup version: {__version__}')
    # default to --help
    if args is None:
        args = sys.argv[1:] or ['--help']

    # parse command line arguments
    options = cli.get_parser().parse_args(args=args)

    # cli debugging
    if options.debug:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout, force=True)

    # process command
    try:
        options.func(options)
    except Exception:  # noqa
        logger.exception(f'Failed to process command: {args}')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
