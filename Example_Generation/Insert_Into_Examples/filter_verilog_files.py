import os
import re
import subprocess
import time
from pathlib import Path

# from pyverilog.vparser.ast import ModuleDef
# from pyverilog.vparser.parser import parse
from hdlConvertor import HdlConvertor
from hdlConvertorAst.hdlAst import HdlModuleDef
from hdlConvertorAst.hdlAst._structural import HdlContext
from hdlConvertorAst.language import Language

from CONFIG import FILTERED_FILES_DIR, FILTERED_FILES_DIR, TEST_DIR, UNFILTERED_FILES_DIR

INPUT_DIR = UNFILTERED_FILES_DIR
OUTPUT_DIR = FILTERED_FILES_DIR

def filter_with_slang(file: Path) -> bool:
    relative_file_path = file.resolve().relative_to(Path.cwd())
    
    cmd = ["slang", "--parse-only", "-q", "-Wnone" , str(relative_file_path)]
    result = subprocess.run(cmd)

    if result.returncode == 0:
        return True
    else:
        return False

def filter_non_modules(file: Path) -> bool:
    print(f"Attempting to parse {file} with hdlConvertor...")

    convertor = HdlConvertor()

    if file.suffix == '.v':
        lang = Language.VERILOG
    elif file.suffix == '.sv':
        lang = Language.SYSTEM_VERILOG

    try:
        parsed_file: HdlContext = convertor.parse(
            filenames=[os.fspath(file)],
            language=lang,
            incdirs=[]
        )
        if any(isinstance(obj, HdlModuleDef) for obj in parsed_file.objs):
            return True
        else:
            return False
        pass
    except Exception as e:
        return False

def main():
    start_time = time.perf_counter()

    count_parse_success = 0
    count_parse_fail = 0
    count_slang_success = 0
    count_slang_fail = 0

    for file in INPUT_DIR.iterdir():
        parse_fail = False
        slang_fail = False

        print(f"Processing file: {file.name}")
        if (not file.is_file()) and file.suffix == ".v":
            continue

        if filter_non_modules(file):
            count_parse_success += 1
            print(f"{file.name} contains a module definition.")
        else:
            count_parse_fail += 1
            parse_fail = True
            print(f"Failed to parse {file.name} with pyverilog or it does not contain a module definition.")

        if filter_with_slang(file):
            count_slang_success += 1
            print(f"Successfully compiled {file.name} with slang Verilog")
        else:
            count_slang_fail += 1
            slang_fail = True
            print(f"Failed to compile {file.name} with slang Verilog")
        if (count_slang_fail + count_slang_success) % 25 == 0:
            print(f"\n(Parse) Processed {count_parse_success + count_parse_fail} files... (passed={count_parse_success}, failed={count_parse_fail})\n")
            print(f"\n(slang Verilog) Processed {count_slang_success + count_slang_fail} files... (passed={count_slang_success}, failed={count_slang_fail})\n")

        if parse_fail or slang_fail:
            print(f"Removing {file.name} from output directory due to failure...")
            file.unlink()
        else:
            print(f"Moving {file.name} to {OUTPUT_DIR} directory...")
            OUTPUT_DIR.mkdir(exist_ok=True)

            counter = 1
            new_file = OUTPUT_DIR / file.name

            while new_file.exists():
                new_file = OUTPUT_DIR / f"{file.stem}.{counter}{file.suffix}"
                counter += 1
            try:
                file.rename(new_file)
            except FileExistsError as e:
                print(f"Failed to move {file.name}: {e}")
                print(f"Removing {file.name} from output directory due to failure...")
                file.unlink()

        print(f"\n----------------------------------------\n")


    print(f"Parsing Summary: {count_parse_success} passed, {count_parse_fail} failed")
    print(f"Slang Summary: {count_slang_success} passed, {count_slang_fail} failed")

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    
    print()
    print(f"Time elapsed: {elapsed_time:.4f} seconds")

if __name__ == "__main__":
    main()