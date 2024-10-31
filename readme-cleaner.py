import os
import re


def process_readme(file_path, replacements: dict[str, str]):
    with open(file_path, 'r') as file:
        content = file.read()
    
    for pattern, replacement in replacements.items():
        content = re.sub(pattern, replacement, content)
    
    with open(file_path, 'w') as file:
        file.write(content)

def process_files(directory: str, replacements: dict[str, str]):
    for subdir, _, files in os.walk(directory):
        for file in files:
            if file.lower() == 'readme.md':
                process_readme(os.path.join(subdir, file), replacements)

def process_malware_injection_technique_readmes(rootDir: str):
    rootDir += ''

    replacements = {
        r'\[Direct Injection\]\(.*?\)': '[Direct Injection](2024-08-14-malware-inject.md)',
        r'\[DLL Injection\]\(.*?\)': '[DLL Injection](2024-08-11-malware-inject.md)',
        r'\[DLL Injection example\]\(.*?\)': '[DLL Injection](2024-08-11-malware-inject.md)',
        r'\[dummy target\]\(.*?\)': 'dummy target'
    }

    process_files(replacements)


rootDir = os.getcwd()
process_malware_injection_technique_readmes(rootDir)