import sys

from tufup import main

# __main__.py allows us to call the package using `python -m tufup`
# https://docs.python.org/3/library/__main__.html#main-py-in-python-packages
try:
    main()  # return code 0
except Exception as e:
    sys.exit(f'error: {e}')  # return code 1
