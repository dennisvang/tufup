# Contribution guidelines

... 

## Coding conventions and rules of thumb

- minimize functionality to the absolute necessities
- minimize the number of external dependencies
- write tests
- try to follow [PEP 8][1] whenever it makes sense
- be explicit (and other good ideas from [PEP 20][2])
- be consistent
- keep it simple:
  - prefer readability over "efficiency" 
  - "avoid clever tricks like the plague" (as in [EWD 340][3])
- regarding doc strings, comments, log messages, and so on and so forth:
  - please do not try to be witty
  - please do not use exclamation points unless absolutely necessary
- ...

## Some specific preferences

- use `pathlib` instead of `os.path`, whenever possible
- ...


[1]: https://peps.python.org/pep-0008/
[2]: https://peps.python.org/pep-0020/
[3]: https://www.cs.utexas.edu/users/EWD/transcriptions/EWD03xx/EWD340.html