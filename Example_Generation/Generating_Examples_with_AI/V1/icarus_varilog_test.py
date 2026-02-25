import subprocess
import os


def run_msys(cmd):
    return subprocess.run(
        [
            r"C:\msys64\usr\bin\bash.exe",
            "-lc",
            f"export PATH=/mingw64/bin:$PATH && {cmd}"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
text = "cd C:/Users/parks/OneDrive/Documents/UC/Research/Spring_2026/Initial_AI_Testing/Prompts/1245-1 && iverilog -o test.vvp 1245-1-response-code.v"

prompts_dir = "C:/Users/parks/OneDrive/Documents/UC/Research/Spring_2026/Initial_AI_Testing/Prompts"
cwe_prefixes = ["1245", "1233", "226", "1431"]

for prefix in cwe_prefixes:
    for i in range(1, 13):
        prompt_id_dir = prompts_dir + f"/{prefix}" + f"/{prefix}-{i}"
        code_file_name = f"{prefix}-{i}-gpt-5_2-response-code.v"
        output_file_name = f"{prefix}-{i}-gpt-5_2-response-code.vvp"

        result = run_msys(f"cd {prompt_id_dir} && iverilog -o {output_file_name} {code_file_name}")

        print(f"Results for {prefix}-{i}:")
        print("STDOUT:")
        print(result.stdout)
        print("STDERR:")
        print(result.stderr)
        print()