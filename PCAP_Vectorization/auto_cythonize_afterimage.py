import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "AfterImage.py"
PYX_TARGET = ROOT / "AfterImage_extrapolate.pyx"
C_TARGET = ROOT / "AfterImage_extrapolate.c"


def generate_pyx():
    if not SOURCE.exists():
        raise FileNotFoundError(f"{SOURCE.name} does not exist")
    shutil.copyfile(SOURCE, PYX_TARGET)
    print(f"Generated {PYX_TARGET.name} from {SOURCE.name}")


def generate_c():
    if not PYX_TARGET.exists():
        generate_pyx()
    cmd = [
        sys.executable,
        "-m",
        "cython",
        "-3",
        str(PYX_TARGET),
        "-o",
        str(C_TARGET),
    ]
    subprocess.check_call(cmd, cwd=ROOT)
    print(f"Generated {C_TARGET.name} from {PYX_TARGET.name}")


def build_extension():
    if not PYX_TARGET.exists():
        generate_pyx()
    cmd = [sys.executable, "setup.py", "build_ext", "--inplace"]
    subprocess.check_call(cmd, cwd=ROOT)
    print("Built AfterImage_extrapolate extension")


def main():
    parser = argparse.ArgumentParser(
        description="Generate and build AfterImage_extrapolate from AfterImage.py."
    )
    parser.add_argument("--pyx-only", action="store_true", help="Only generate .pyx")
    parser.add_argument("--c-only", action="store_true", help="Generate .pyx and .c")
    parser.add_argument("--build-only", action="store_true", help="Only build the extension")
    args = parser.parse_args()

    if args.pyx_only:
        generate_pyx()
    elif args.c_only:
        generate_c()
    elif args.build_only:
        build_extension()
    else:
        generate_pyx()
        generate_c()
        build_extension()


if __name__ == "__main__":
    main()
