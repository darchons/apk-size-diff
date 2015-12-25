diff.py
=======

## Usage

    diff.py <before-apk> <after-apk>

## Output

Each line contains a +/- number indicating size change in bytes followed by the
file name, separated by space.

fennec-diff.py
==============

## Usage

    fennec-diff.py <before-apk> <after-apk>

## Output

Same as diff.py

## Note

For input apk name `foo.multi.android-arm.apk`, the script expects a zip file
named `foo.en-US.android-arm.crashreporter-symbols.zip` in the same directory.
The zip file contains breakpad symbols for the .so binaries in the apk.
