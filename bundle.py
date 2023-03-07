import os
import sys
import subprocess

import angr
import pyvex
import cle
import z3
import capstone

def make_common_options(for_chess=False):
    include_data = [
        (
            os.path.join(os.path.dirname(cle.__file__), "backends/elf/relocation"),
            "cle/backends/elf/relocation",
        ),
        (
            os.path.join(os.path.dirname(cle.__file__), "backends/pe/relocation"),
            "cle/backends/pe/relocation",
        ),
        (
            os.path.join(os.path.dirname(angr.__file__), "analyses/identifier/functions"),
            "angr/analyses/identifier/functions",
        ),
        (os.path.join(os.path.dirname(angr.__file__), "procedures"), "angr/procedures"),
    ]

    include_libs = [
        (
            os.path.join(os.path.dirname(pyvex.__file__), "lib"),
            "pyvex/lib"
        ),
        (os.path.join(os.path.dirname(z3.__file__), "lib"), "z3/lib"),
        (os.path.join(os.path.dirname(angr.__file__), "lib"), "angr/lib"),
        (capstone._path, "capstone/lib"),
    ]

    all_mappings = [
        (";" if sys.platform.startswith("win") else ":").join(mapping) for mapping in (include_data + include_libs)
    ]
    args = (
        [
            "pyinstaller",
        ]

        + [
            "--name=stack-detector",
            "-w"
        ]
    )

    for mapping in all_mappings:
        args.append("--add-data")
        args.append(mapping)
    args.append("main.py")
    return args

def make_bundle(onefile=False, onedir=False, for_chess=False):
    """
    Execute the pyinstaller command.
    """
    args = make_common_options(for_chess=for_chess)

    if onefile:
        file_args = [*args]
        file_args.append("--onefile")
        file_args.append("--distpath")
        file_args.append("onefile")
        subprocess.run(file_args, check=True, cwd=os.path.dirname(os.path.realpath(__file__)))

    if onedir:
        dir_args = [*args]
        dir_args.append("--distpath")
        dir_args.append("onedir")
        subprocess.run(dir_args, check=True, cwd=os.path.dirname(os.path.realpath(__file__)))


def main():
    for_chess = "--chess" in sys.argv
    onefile = "--onefile" in sys.argv
    onedir = "--onedir" in sys.argv
    make_bundle(onefile=onefile, onedir=onedir, for_chess=for_chess)


if __name__ == "__main__":
    main()