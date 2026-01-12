import os

from InquirerPy import inquirer


def file_explorer(start_path: str=".", save_file: bool=False, file_extensions_allowed:list[str]=[]) -> str:
    """Creates a file explorer allowing the user to select a file or folder

    Args:
        start_path (str): Specifies the starting folder of the file explorer, Defaults to "."
        save_file (bool): If True shows only folders where the file can be saved, if False shows all files, Defaults to False
        file_extensions_allowed (list[str]): A list of file extensions that are allowed to be selected by the user, Defaults to []

    Returns:
        str: Selected folder or file path
    """
    current_path =start_path

    while True:
        folder_items = os.listdir(current_path)

        #Add choices for navigation
        choices = []

        if not save_file:
            #If the user can select files, add all items at current path 
            if all(file.endswith(tuple(file_extensions_allowed)) for file in folder_items):
                #Only allow the user to select a folder for detection if all files are in an allowed format
                choices.append("Select this folder")

            #Filter files with extensions that are not allowed
            for item in folder_items:
                if os.path.isdir(os.path.join(current_path, item)):
                    choices.append(item)
                else:
                    #Check if file type is allowed
                    _, extension = os.path.splitext(item)
                    if extension in file_extensions_allowed:
                        choices.append(item)
        else:
            #Else only show folders (Used when selecting a folder for saving results)
            choices.append("Select this folder")
            choices.append("(New Folder)")
            sub_folders = []
            for item in folder_items:
                if os.path.isdir(os.path.join(current_path, item)):
                    sub_folders.append(item)
            choices.extend(sub_folders)


        #Allow users to go up the folder tree if not at the starting folder
        if not os.path.normpath(current_path) ==  os.path.normpath(start_path):
            choices.append("..")

        print()
        user_choice = inquirer.select(
            message=f"Browsing {current_path}",
            choices=choices,
            height=len(choices)*2
        ).execute()

        match user_choice:
            case "Select this folder":
                return current_path
            case "(New Folder)":
                new_folder_name: str = inquirer.text(
                    message="Enter a name for the new folder"
                ).execute()
                new_folder_path = os.path.join(current_path, new_folder_name)

                try:
                    os.makedirs(new_folder_path, exist_ok=True)
                    print(f"\nNew folder created: {new_folder_name}\n")
                    current_path = new_folder_path
                except:
                    print(f"\nCould not create folder: {new_folder_name}\n")
            case "..":
                current_path = os.path.dirname(current_path)
            case _:
                selected_path = os.path.join(current_path, user_choice)
                if os.path.isdir(selected_path):
                    current_path = selected_path
                else:
                    return selected_path

def file_selector(message: str="Select a folder or files", start_path: str=".", save_file:bool=False, file_extensions_allowed:list[str]=[]) -> str:
    """
    Creates a file explorer allowing the user to select a folder or file

    Args:
        message (str): Message that is displayed to user specifying what action to take, Defaults to "Select a folder or file"
        start_path (str): Specifies the starting folder of the file explorer, Defaults to "."
        save_file (bool): If True shows only folders where the file can be saved, if False shows all files, Defaults to False
        file_extensions_allowed (list[str]): A list of file extensions that are allowed to be selected by the user, Defaults to []

    Returns:
        str: Folder or file path
    """
    print(f"\n{message}")
    selected_path = file_explorer(start_path, save_file, file_extensions_allowed)
    return selected_path