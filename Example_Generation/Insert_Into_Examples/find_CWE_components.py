#Find if each filtered Verilog file has the components for any CWE and is suitable for vulnerability insertion
# CWE-1245: case statement
# CWE-1233: lock bit
# CWE-226: reset register
# CWE-1431: cryptographic module name

import re
import os
import shutil
import time
from pathlib import Path

# from pyverilog.vparser.ast import CaseStatement, ModuleDef, Node, Reg
# from pyverilog.vparser.parser import parse
from hdlConvertor import HdlConvertor
from hdlConvertorAst.hdlAst import * # HdlModuleDef, HdlStmCase, HdlIdDef, HdlDirection, HdlOpType, HdlOp, HdlValueInt, HdlValueId
from hdlConvertorAst.hdlAst._structural import HdlContext
from hdlConvertorAst.language import Language
from hdlConvertorAst.to.hdl_ast_visitor import HdlAstVisitor

from CONFIG import (
    CWE_226_DIR,
    CWE_1233_DIR,
    CWE_1245_DIR,
    CWE_1431_DIR,
    UNSORTED_DIR,
    FILTERED_FILES_DIR,
    TEST_DIR,
)

INPUT_DIR = TEST_DIR

class ASTVisitor(HdlAstVisitor):
    #1233: in hdliddef Find possible lock bit registers, when running into a if statement or ternary, check if the conditional contains the lock bit register and protects an assignment

    def __init__(self):
        super().__init__()
        self.case_found = False
        self.defined_registers = set()
        self.possible_lock_bit_registers = set()
        self.confirmed_lock_bit_registers = set()
        self.possible_reset_registers = set()
        self.confirmed_reset_registers = set()
        self.cryptographic_module = False

    def visit_HdlStmCase(self, o: HdlStmCase):
        self.case_found = True
        return super().visit_HdlStmCase(o)

    def visit_HdlModuleDef(self, o: HdlModuleDef):
        crypto_module_pattern = re.compile(
            r'(?i)(?<![A-Za-z0-9])(?:aes\d*|sha\d*|crypto|hmac|md5|otp(?:_ctrl|_scrmbl)?|chacha|scrambl|cipher|hash|mac|keccak)(?![A-Za-z0-9])'
        )
        module_name = o.module_name.val
        if crypto_module_pattern.search(module_name) and "wrapper" not in module_name:
            self.cryptographic_module = True
        return super().visit_HdlModuleDef(o)
    
    def visit_HdlIdDef(self, o: HdlIdDef):
        lock_name_patterns = [r"\block\b", r"lck", r"(?<!c)lk(?!c)"]
        if any(re.search(pattern, o.name.lower()) for pattern in lock_name_patterns):
            if o.direction != HdlDirection.OUT:
                self.possible_lock_bit_registers.add(o.name)

        reset_name_patterns = [r"reset", r"rst"] 
        if any(re.search(pattern, o.name.lower()) for pattern in reset_name_patterns):
            if o.direction == HdlDirection.IN:
                self.possible_reset_registers.add(o.name)

        self.defined_registers.add(o.name)
        return super().visit_HdlIdDef(o)
    
    def visit_HdlStmIf(self, o: HdlStmIf):
        conditional_variables = self.extract_conditional_variables(o.cond)
        for reg in self.possible_lock_bit_registers:
            if reg in conditional_variables:
                self.confirmed_lock_bit_registers.add(reg)

        for reg in self.possible_reset_registers:
            if reg in conditional_variables:
                self.confirmed_reset_registers.add(reg)
        return super().visit_HdlStmIf(o)
    
    def visit_HdlOp(self, o: HdlOp):
        if o.fn == HdlOpType.TERNARY:
            conditional_variables = self.extract_conditional_variables(o.ops[0])
            for reg in self.possible_lock_bit_registers:
                if reg in conditional_variables:
                    self.confirmed_lock_bit_registers.add(reg)

            for reg in self.possible_reset_registers:
                if reg in conditional_variables:
                    self.confirmed_reset_registers.add(reg)
        return super().visit_HdlOp(o)
    
    def extract_conditional_variables(self, node: HdlValueId | HdlOp | HdlValueInt):
        if node is None:
            return set()
        
        if isinstance(node, HdlValueId):
            return {node.val}
        elif isinstance(node, HdlValueInt):
            return set()
        elif isinstance(node, HdlOp):
            variables = set()
            for op in node.ops:
                variables.update(self.extract_conditional_variables(op))
        
            return variables
    
def copy_without_overwrite(src: Path, dst: Path):
    # return #TO-DO: Remove this line to enable file copying
    if dst.exists():
        new_dst = dst
        counter = 1

        while new_dst.exists():
            new_dst = dst.with_name(f"{dst.stem}.{counter}{dst.suffix}")
            counter += 1

        dst = new_dst
    shutil.copy(src, dst)

def main():  
    start_time = time.perf_counter()

    print(f"\nProcessing files in {INPUT_DIR}...\n")
    print("----------------------------------------\n")

    count_CWE_1245_files = 0
    count_CWE_1233_files = 0
    count_CWE_226_files = 0
    count_CWE_1431_files = 0
    count_total = 0

    for file in INPUT_DIR.iterdir():
        count_total += 1
        print(f"Processing {file}...\n")

        found_cwe_components = 0

        convertor = HdlConvertor()

        #Determine file language
        if file.suffix == '.v':
            lang = Language.VERILOG
        elif file.suffix == '.sv':
            lang = Language.SYSTEM_VERILOG
        else:
            raise ValueError("Unsupported file type")
        
        try:
            parsed_file: HdlContext = convertor.parse(
                filenames=[os.fspath(file)],
                language=lang,
                incdirs=[]
            )
            module_def: HdlModuleDef = parsed_file.objs[0]
        except Exception as e:
            print(f"Error parsing {file.name}: {e}")
            file.unlink()
            continue
        
        visitor = ASTVisitor()
        try:
            visitor.visit_HdlModuleDef(module_def)
        except Exception as e:
            print(f"Error traversing AST for {file.name}: {e}")
            file.unlink()
            continue
        visitor.defined_registers.discard(None)
        visitor.confirmed_lock_bit_registers.difference_update(visitor.confirmed_reset_registers)
        visitor.confirmed_reset_registers.difference_update(visitor.confirmed_lock_bit_registers)
    
        #Check for CWE-1245 components (case statement)
        if visitor.case_found:
            found_cwe_components += 1
            count_CWE_1245_files += 1
            print(f"{file} contains components for CWE-1245 (case statement). Copying file to {CWE_1245_DIR}...")
            CWE_1245_DIR.mkdir(parents=True, exist_ok=True)
            dst = CWE_1245_DIR / file.name
            copy_without_overwrite(file, dst)
        else:
            print(f"{file} does NOT contain components for CWE-1245 (case statement).")

        print()

        #Check for CWE-1233 components (lock bit register)
        if len(visitor.confirmed_lock_bit_registers) > 0:
            found_cwe_components += 1
            count_CWE_1233_files += 1
            print(f"{file} contains components for CWE-1233 (lock bit). Copying file to {CWE_1233_DIR}...")
            CWE_1233_DIR.mkdir(parents=True, exist_ok=True)
            dst = CWE_1233_DIR / file.name
            copy_without_overwrite(file, dst)
        else:
            print(f"{file} does NOT contain components for CWE-1233 (lock bit).")

        print()

        #Check for CWE-226 components (reset register)
        if len(visitor.confirmed_reset_registers) > 0:
            found_cwe_components += 1
            count_CWE_226_files += 1
            print(f"{file} contains components for CWE-226 (reset register). Copying file to {CWE_226_DIR}...")
            CWE_226_DIR.mkdir(parents=True, exist_ok=True)
            dst = CWE_226_DIR / file.name
            copy_without_overwrite(file, dst)
        else:
            print(f"{file} does NOT contain components for CWE-226 (reset register).")

        print()

        #Check for CWE-1431 components (cryptographic module)
        if visitor.cryptographic_module:
            found_cwe_components += 1
            count_CWE_1431_files += 1
            print(f"{file} contains components for CWE-1431 (cryptographic module name). Copying file to {CWE_1431_DIR}...")
            CWE_1431_DIR.mkdir(parents=True, exist_ok=True)
            dst = CWE_1431_DIR / file.name
            copy_without_overwrite(file, dst)
        else:
            print(f"{file} does NOT contain components for CWE-1431 (cryptographic module name).")

        if found_cwe_components == 0:
            print(f"{file} contains components for no CWE. Copying file to {UNSORTED_DIR}...")
            UNSORTED_DIR.mkdir(parents=True, exist_ok=True)
            dst = UNSORTED_DIR / file.name
            copy_without_overwrite(file, dst)

        # file.unlink() TO-DO: Remove this line to enable file deletion after processing

        print(f"\n----------------------------------------\n")

    print(f"Files with CWE-1245 Components: {count_CWE_1245_files}")
    print(f"Files with CWE-1233 Components: {count_CWE_1233_files}")
    print(f"Files with CWE-226 Components: {count_CWE_226_files}")
    print(f"Files with CWE-1431 Components: {count_CWE_1431_files}")
    print(f"Total Files Processed: {count_total}")

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    
    print()
    print(f"Time elapsed: {elapsed_time:.4f} seconds")


if __name__ == "__main__":
    main()