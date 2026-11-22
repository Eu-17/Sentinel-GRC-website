"""Apply per-process limits before replacing this child with an offline TShark reader."""
import os
import resource
import sys


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 6))
    resource.setrlimit(resource.RLIMIT_FSIZE, (3 * 1024**2, 3 * 1024**2))
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
    os.execv(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
