# IridiumScorpion
This is a proof of concept cpython virus, which infects compatible pyc files in nearby `__pycache__` directories,
which Python sometimes automatically populates (and uses) for optimisation purposes.
Unlike [BismuthScorpion](https://github.com/EvelynSubarrow/BismuthScorpion), every file is infected, but unlike
BismuthScorpion, this will only work against a target of the same version, and there is no obfuscation.

## Compatibility
This has been tested to work with python 3.4, 3.5, 3.6, and 3.7. It should be compatible with 3.2, but I haven't
tested this.

## Licence
[Creative Commons BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) for now.

## References
* [PEP 3147](https://www.python.org/dev/peps/pep-3147/) - 3x .pyc format and caching mechanics
* [PEP 552](https://www.python.org/dev/peps/pep-0552/) - 3.7+ .pyc format
* [Reading pyc file (Python 3.5.2) - amedama](https://qiita.com/amedama/items/698a7c4dbdd34b03b427) - 3.3..3.6 .pyc format
* [Pytype magic.py](https://github.com/google/pytype/blob/master/pytype/pyc/magic.py) - Magic number list
