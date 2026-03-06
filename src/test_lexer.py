import sys
import os

# Add src to path to import lexer
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from lexer import lexer

def test_lexer(file_path):
    with open(file_path, 'r') as f:
        data = f.read()

    # Give the lexer some input
    lexer.input(data)

    print(f"--- Tokenizing {file_path} ---")
    # Tokenize
    while True:
        tok = lexer.token()
        if not tok: 
            break      # No more input
        print(tok)

if __name__ == "__main__":
    # Path to example policy
    example_path = os.path.join(os.path.dirname(__file__), '..', 'examples', 'policy1.rbac')
    test_lexer(example_path)
