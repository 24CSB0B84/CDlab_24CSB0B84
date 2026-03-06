import sys
import os
import glob

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from parser import parser
from ast_nodes import Policy

def test_parser(file_path):
    print(f"\n{'='*20} Parsing {os.path.basename(file_path)} {'='*20}")
    try:
        with open(file_path, 'r') as f:
            data = f.read()
            
        result = parser.parse(data)
        
        if result:
            print("Parsing Successful!")
            print(result)
        else:
            print("Parsing Failed (result is None).")
            
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    examples_dir = os.path.join(os.path.dirname(__file__), '..', 'examples')
    rbac_files = sorted(glob.glob(os.path.join(examples_dir, '*.rbac')))
    
    for file_path in rbac_files:
        test_parser(file_path)
