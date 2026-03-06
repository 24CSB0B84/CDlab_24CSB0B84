import ply.yacc as yacc
from lexer import tokens
import ast_nodes as ast

# Parsing rules

def p_policy(p):
    '''policy : statement_list'''
    p[0] = ast.Policy(statements=p[1])

def p_statement_list_multiple(p):
    '''statement_list : statement statement_list'''
    p[0] = [p[1]] + p[2]

def p_statement_list_single(p):
    '''statement_list : statement'''
    p[0] = [p[1]]

def p_statement(p):
    '''statement : role_def
                 | perm_def
                 | user_def
                 | sod_def'''
    p[0] = p[1]

# Permission Definition
def p_perm_def(p):
    '''perm_def : PERMISSION ID SEMI'''
    p[0] = ast.Permission(name=p[2])

# Role Definition
def p_role_def(p):
    '''role_def : ROLE ID LBRACE role_body RBRACE'''
    # Flatten role body to extract parents and permissions
    parents = []
    permissions = []
    
    # role_body is a list of tuples like ('INHERITS', ['r1', 'r2']) or ('PERMISSIONS', ['p1'])
    if p[4]:
        for item in p[4]:
            if item[0] == 'INHERITS':
                parents.extend(item[1])
            elif item[0] == 'PERMISSIONS':
                permissions.extend(item[1])
            
    p[0] = ast.Role(name=p[2], parents=parents, permissions=permissions)

def p_role_body_recur(p):
    '''role_body : role_attr role_body'''
    if p[2] is None:
        p[0] = [p[1]]
    else:
        p[0] = [p[1]] + p[2]

def p_role_body_empty(p):
    '''role_body : '''
    p[0] = []

def p_role_attr_inherits(p):
    '''role_attr : INHERITS id_list SEMI'''
    p[0] = ('INHERITS', p[2])

def p_role_attr_permissions(p):
    '''role_attr : PERMISSIONS id_list SEMI'''
    p[0] = ('PERMISSIONS', p[2])

# User Definition
def p_user_def(p):
    '''user_def : USER ID ENGAGES id_list SEMI'''
    p[0] = ast.User(name=p[2], roles=p[4])

# SOD Definition
def p_sod_def(p):
    '''sod_def : CONFLICT ID AND ID SEMI'''
    p[0] = ast.Conflict(role1=p[2], role2=p[4])

# Helper: ID List
def p_id_list_multi(p):
    '''id_list : ID COMMA id_list'''
    p[0] = [p[1]] + p[3]

def p_id_list_single(p):
    '''id_list : ID'''
    p[0] = [p[1]]

# Error rule for syntax errors
def p_error(p):
    if p:
        print(f"Syntax error at token '{p.value}' (type: {p.type}) on line {p.lineno}")
        # Panic mode recovery: Skip tokens until a semicolon or closing brace is found
        while True:
            tok = parser.token()
            if not tok or tok.type in ['SEMI', 'RBRACE']:
                break
        parser.restart()
    else:
        print("Syntax error at EOF")

# Build the parser
parser = yacc.yacc()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python parser.py <policy_file>")
        sys.exit(1)
        
    filename = sys.argv[1]
    
    try:
        with open(filename, 'r') as f:
            data = f.read()
            
        print(f"--- Parsing {filename} ---")
        result = parser.parse(data)
        
        if result:
            print("Parsing Successful!")
            print(result)
        else:
            print("Parsing Failed.")
            
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
