# Release

Steps for building a release package:

1. Edit `pyproject.toml` and remove "-dev" from the `version` key.
2. `make extras`
3. Commit changes.
4. Push repo.
5. Tag commit with "vVERSION".
6. Push tag.
7. Check [Releases](https://github.com/lovette/jsonlogalert/releases) after [build release action](https://github.com/lovette/jsonlogalert/actions) is complete.

Then repeat the steps above with "-dev" appended to the version and without tagging the commit.
