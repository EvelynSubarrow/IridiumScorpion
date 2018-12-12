# IridiumScorpion
This is a proof of concept compiled python virus, which infects compatible pyc files in neary `__pycache__` directories,
which Python sometimes automatically populates (and uses) for optimisation purposes. Unlike BismuthScorpion, every
file is infected.

## Compatibility
This has been tested to work with python 3.4, 3.5, 3.6, and doesn't yet work on 3.7
