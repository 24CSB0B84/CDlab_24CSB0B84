from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Node:
    pass

@dataclass
class Policy(Node):
    statements: List[Node] = field(default_factory=list)

    def __repr__(self):
        return f"Policy(\n  statements={self.statements}\n)"

@dataclass
class Permission(Node):
    name: str

    def __repr__(self):
        return f"Permission(name='{self.name}')"

@dataclass
class Role(Node):
    name: str
    parents: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)

    def __repr__(self):
        return f"Role(name='{self.name}', parents={self.parents}, permissions={self.permissions})"

@dataclass
class User(Node):
    name: str
    roles: List[str] = field(default_factory=list)

    def __repr__(self):
        return f"User(name='{self.name}', roles={self.roles})"

@dataclass
class Conflict(Node):
    role1: str
    role2: str

    def __repr__(self):
        return f"Conflict(role1='{self.role1}', role2='{self.role2}')"
