# Release

Steps for building a release package:

1. Edit `pyproject.toml` and remove "-dev" from the `version` key.
1. Activate virtualenv.
1. `make distclean`
1. `make install-dev`
1. `jsonlogalert --version`
1. `make extras`
1. Commit changes with message "Version bump."
1. Push repo.
1. Tag commit with "vVERSION".
1. Push tag.
1. Check [Releases](https://github.com/lovette/jsonlogalert/releases) after [build release action](https://github.com/lovette/jsonlogalert/actions) is complete.

Then repeat the steps above with "-dev" appended to the version and without tagging the commit.
