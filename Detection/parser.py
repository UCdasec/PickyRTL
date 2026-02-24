import json
import os
import re
from pathlib import Path

from file_selector import file_selector


def parse_file(file_path:str):
    """Parse an HDL file and convert it to JSON format.

    Args:
        file_path (str): Path to the HDL file to be parsed.
    """
    from hdlConvertor import HdlConvertor
    from hdlConvertorAst.hdlAst import HdlDirection, HdlModuleDec, HdlModuleDef
    from hdlConvertorAst.hdlAst._structural import HdlContext
    from hdlConvertorAst.language import Language
    from hdlConvertorAst.to.json import ToJson

    convertor = HdlConvertor()
    to_json = ToJson()

    #Determine file language
    if file_path.endswith('.v'):
        lang = Language.VERILOG
    elif file_path.endswith('.sv'):
        lang = Language.SYSTEM_VERILOG
    else:
        raise ValueError("Unsupported file type")
    
    #Determine if file has any includes
    pattern = re.compile(r'^\s*`include\s+["<](.+)[">]', re.MULTILINE)
    with open(file_path, 'r', encoding='utf-8') as f:
        includes = pattern.findall(f.read())

    if len(includes) > 0:
        include_dirs_directory = os.path.join(Path(Path(file_path).parent).parent, 'Include_Dirs')
        include_dirs = ['.', include_dirs_directory]
    else:
        include_dirs = ['.']

    #Parse file and turn into JSON
    try:
        parsed_file: HdlContext = convertor.parse(
            filenames=[file_path], 
            language=lang, 
            incdirs=include_dirs
        )
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
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return None

def parse_folder(folder_path:str):
    """Parse all files in a folder and convert them to JSON format.

    Args:
        folder_path (str): Path to the folder containing HDL files to be parsed.
    """
    for file in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file)
        parse_file(file_path)

def parse():
    """Creates a file explorer to select an HDL file or folder of HDL files to parse
    """
    selected_path = file_selector(
        message="---Select a folder or file to parse---",
        start_path=Path(__file__).parent.resolve() / "./Examples",
        file_extensions_allowed=['.v', '.sv']
    )
    
    if os.path.isdir(selected_path):
        parse_folder(selected_path)
    elif os.path.isfile(selected_path):
        parse_file(selected_path)
    else:
        print("Invalid Selection. Please Select a Valid File or Folder")
        return



