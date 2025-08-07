from hdlConvertor import HdlConvertor
from hdlConvertorAst.hdlAst import HdlModuleDef, HdlModuleDec, HdlDirection
from hdlConvertorAst.language import Language
from hdlConvertorAst.hdlAst._structural import HdlContext
from hdlConvertorAst.to.json import ToJson
import os
from pathlib import Path
import json


def parse_file(file_path: str) -> str:
    """Parse an HDL file and convert it to JSON format.

    Args:
        file_path (str): Path to the HDL file to be parsed.
    Returns:
        str: Path to the JSON file containing the parsed HDL data.
    """
    convertor = HdlConvertor()
    to_json = ToJson()

    #Determine file language
    if file_path.endswith('.v'):
        lang = Language.VERILOG
    elif file_path.endswith('.sv'):
        lang = Language.SYSTEM_VERILOG
    elif file_path.endswith('.vhd'):
        lang = Language.VHDL
    else:
        raise ValueError("Unsupported file type")
    
    #Parse file and turn into JSON
    parsed_file: HdlContext = convertor.parse([file_path, ], lang, ['.'])
    parsed_json = to_json.visit_HdlContext(parsed_file)

    folders = file_path.split(os.sep)[:-1]

    #Create JSON file path
    parsed_json_filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Parsed_Files', folders[-2], folders[-1], f"{Path(file_path).stem}_parsed.json")
    os.makedirs(os.path.dirname(parsed_json_filepath), exist_ok=True)

    #Save the JSON file
    with open(parsed_json_filepath, 'w') as f:
        json.dump(parsed_json, f, indent=4)

    print(f"{Path(file_path).name} parsed and saved to: {parsed_json_filepath}")

    return parsed_json_filepath


def parse_folder(folder_path: str):
    """Parse all files in a folder and convert them to JSON format.

    Args:
        folder_path (str): Path to the folder containing HDL files to be parsed.
    Returns:
        list(str): List of paths to the JSON files containing the parsed HDL data.
    """
    parsed_file_paths = []
    for file in os.listdir(folder_path):
        if "9" in file:
            continue
        file_path = os.path.join(folder_path, file)
        parsed_file_paths.append(parse_file(file_path))

    return parsed_file_paths
    
def main():
    # file_path = "/media/sf_Summer_Research/CWE_Examples/CWE-1245/Vulnerable_Code/example_9_vulnerable.sv"
    # parse_file(file_path)

    folder_path = "/media/sf_Summer_Research/CWE_Examples/CWE-1245/Fixed_Code"
    x = parse_folder(folder_path)

if __name__ == "__main__":
    main()



