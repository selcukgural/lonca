# Licence.

import os

if TYPE_CHECKING:
    def a():
        return 10
else:
    def b():
        return 2

try:
    def c():
        return 30
except ImportError:
    def c():
        return 4

if __name__ == "__main__":
    def main():
        return 5
