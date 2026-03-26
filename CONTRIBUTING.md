## Contributing to Yail or other Orange's Projects

### Prerequisites

- A working up-to-date yail installation
- C++ knowledge
- Git knowledge
- Ability to ask for help (Feel free to create empty pull-request or PM a maintainer
  in [Telegram](https://t.me/orange_cpp))

### Setting up Yail

Please read INSTALL.md file in repository

###  Pull requests and Branches

In order to send code back to the official Yail repository, you must first create a copy of Yail on your github
account ([fork](https://help.github.com/articles/creating-a-pull-request-from-a-fork/)) and
then [create a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/) back to Yail.

Yail development is performed on multiple branches. Changes are then pull requested into master. By default, changes
merged into master will not roll out to stable build users unless the `main` tag is updated.

### Code-Style

The orange code-style can be found in `.clang-format`.

### Building

Yail has already created the  `cmake-build` and `out` directories where cmake/bin files are located. By default, you
can build Yail by running `cmake --build cmake-build/build/windows-release --target yail -j 6` in the source
directory.
