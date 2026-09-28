"""Print a salted hash; never prints or stores the password."""
from getpass import getpass
from argon2 import PasswordHasher
if __name__ == '__main__':
    print(PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1).hash(getpass('Initial password: ')))
