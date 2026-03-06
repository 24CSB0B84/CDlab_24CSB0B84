import ply.lex as lex

# List of token names.   This is always required
tokens = (
   'ROLE',
   'PERMISSION',
   'USER',
   'CONFLICT',
   'AND',
   'INHERITS',
   'PERMISSIONS',
   'ENGAGES',
   'ID',
   'LBRACE',
   'RBRACE',
   'SEMI',
   'COMMA',
)

# Reserved words
reserved = {
   'role': 'ROLE',
   'permission': 'PERMISSION',
   'user': 'USER',
   'conflict': 'CONFLICT',
   'and': 'AND',
   'inherits': 'INHERITS',
   'permissions': 'PERMISSIONS',
   'engages': 'ENGAGES',
}

# Regular expression rules for simple tokens
t_LBRACE  = r'\{'
t_RBRACE  = r'\}'
t_SEMI    = r';'
t_COMMA   = r','

# A regular expression rule with some action code
def t_ID(t):
    r'[a-zA-Z_][a-zA-Z0-9_]*'
    t.type = reserved.get(t.value,'ID')    # Check for reserved words
    return t

# Define a rule so we can track line numbers
def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)

# A string containing ignored characters (spaces and tabs)
t_ignore  = ' \t'

# Ignore comments
def t_COMMENT(t):
    r'\#.*'
    pass

# Error handling rule
def t_error(t):
    print(f"Illegal character '{t.value[0]}'")
    t.lexer.skip(1)

# Build the lexer
lexer = lex.lex()
