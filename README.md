# IridiumScorpion
This is a proof of concept compiled python virus, which infects compatible pyc files in neary `__pycache__` directories,
which Python sometimes automatically populates (and uses) for optimisation purposes. Unlike BismuthScorpion, every
file is infected.

## Compatibility
This has been tested to work with python 3.4 and 3.5, segfaults after running on 3.6, and does not work at all under 3.7
