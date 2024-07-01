# https://stackoverflow.com/questions/28991015/python3-project-remove-pycache-folders-and-pyc-files
# This will remove all .pyc and .pyo files as well as __pycache__ directories recursively starting from the current directory.
find . | grep -E "(/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf