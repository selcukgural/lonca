# Licence.

import os

if TYPE_CHECKING:
    def a():
        return 1
else:
    def b():
        return 20

try:
    def c():
        return 3
except ImportError:
    def c():
        return 40

if __name__ == "__main__":
    def main():
        return 5

    def more():
        return 6
