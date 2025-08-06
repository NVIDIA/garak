"""garak entry point wrapper"""

import sys

from garak import cli
from garak import api


def main():
    if "--remote" in sys.argv:
        api.run()
    else:
        cli.main(sys.argv[1:])


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
