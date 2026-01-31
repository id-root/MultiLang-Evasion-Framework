import ast
import random
import string
import re

class Polymorph:
    """
    Advanced Polymorphic Engine handling AST mutation and code structure shuffling.
    Replaces the legacy Obfuscator.
    """

    def obfuscate(self, payload, language, level="none"):
        """
        Obfuscate the payload based on language and level.
        """
        if level != "none":
            if language == 'py' or language == 'python':
                payload = self._mutate_python(payload, level)
            elif language in ['c', 'rs', 'rust', 'go']:
                payload = self._mutate_compiled(payload, language, level)
            # else: fallback

        # Always add a unique signature (done after mutation to ensure it persists)
        payload = self._add_unique_signature(payload, language)
        
        return payload

    def _add_unique_signature(self, payload, language):
        sig = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        if language in ['c', 'js', 'go', 'rs', 'rust']:
            return payload + f"\n// Signature: {sig}"
        elif language in ['bash', 'ps1', 'py', 'python']:
            return payload + f"\n# Signature: {sig}"
        return payload

    def _mutate_python(self, payload, level):
        """
        Uses AST to mutate Python code.
        Features: Variable renaming, Control flow restructuring (For -> While).
        """
        try:
            tree = ast.parse(payload)
        except SyntaxError:
            print("[-] Polymorph: Failed to parse Python payload. returning original.")
            return payload

        # 1. Variable/Function Renaming
        if level in ['medium', 'high']:
            renamer = VarRenamer()
            tree = renamer.visit(tree)
        
        # 2. Control Flow Restructuring (For -> While)
        if level == 'high':
            transformer = FlowRestructurer()
            tree = transformer.visit(tree)

        ast.fix_missing_locations(tree)
        return ast.unparse(tree)

    def _mutate_compiled(self, payload, language, level):
        """
        Regex-based structure shuffler for C/Rust/Go.
        Identifies independent function blocks and reorders them.
        """
        if level == "none":
            return payload
            
        # Regex to capture function blocks (heuristic)
        # We assume functions are at top level.
        # Captures: type/fn name(...) { ... }
        
        # We start by splitting lines to handle headers/imports separately
        lines = payload.split('\n')
        headers = []
        code_lines = []
        
        for line in lines:
            if line.strip().startswith('#') or line.strip().startswith('use ') or line.strip().startswith('import ') or line.strip().startswith('//'):
                headers.append(line)
            else:
                code_lines.append(line)
        
        code_body = "\n".join(code_lines)
        
        # Simple block splitter based on braces
        # This is naive but works for well-formatted code
        blocks = []
        current_block = []
        brace_count = 0
        in_block = False
        
        remainder = [] # Things that are not functions (globals, structs)

        # Better approach: Regex to find function definitions
        # Rust: fn name(...) ... { }
        # C: type name(...) { }
        
        # We will split by double newline to approximate blocks, then shuffle
        chunks = code_body.split('\n\n')
        
        # Separate chunks that look like functions
        funcs = []
        others = []
        
        func_indicators = ['fn ', 'void ', 'int ', 'bool ', 'char ', 'long ']
        
        for chunk in chunks:
            if any(ind in chunk for ind in func_indicators) and '{' in chunk and '}' in chunk:
                funcs.append(chunk)
            else:
                others.append(chunk)
                
        random.shuffle(funcs)
        
        # Reassemble
        new_payload = "\n".join(headers) + "\n\n"
        
        # Interleave others and funcs randomly-ish or put others (globals) first
        # Globals usually need to be first.
        new_payload += "\n\n".join(others)
        new_payload += "\n\n"
        new_payload += "\n\n".join(funcs)
        
        return new_payload

# AST Helpers
class VarRenamer(ast.NodeTransformer):
    def __init__(self):
        self.mapping = {}
        self.exclude = {'print', 'range', 'len', 'int', 'str', 'float', 'list', 'dict', 'set', 'open', 'exit', 'os', 'sys', 'socket', 'subprocess'}

    def _get_new_name(self, old_name):
        if old_name in self.exclude or old_name.startswith('__'):
            return old_name
        if old_name not in self.mapping:
            self.mapping[old_name] = ''.join(random.choices(string.ascii_letters, k=8))
        return self.mapping[old_name]

    def visit_Name(self, node):
        # Rename variables
        if isinstance(node.ctx, (ast.Load, ast.Store, ast.Del)):
             node.id = self._get_new_name(node.id)
        return node

    def visit_FunctionDef(self, node):
        node.name = self._get_new_name(node.name)
        self.generic_visit(node)
        return node
        
    def visit_arg(self, node):
        node.arg = self._get_new_name(node.arg)
        return node

class FlowRestructurer(ast.NodeTransformer):
    def visit_For(self, node):
        """
        Convert:
        for i in range(x):
            body
        To:
        _iter = iter(range(x))
        while True:
            try:
                i = next(_iter)
            except StopIteration:
                break
            body
        """
        # Create unique names
        iter_name = "it_" + ''.join(random.choices(string.ascii_lowercase, k=4))
        
        # Assignment: _iter = iter(node.iter)
        assign = ast.Assign(
            targets=[ast.Name(id=iter_name, ctx=ast.Store())],
            value=ast.Call(func=ast.Name(id='iter', ctx=ast.Load()), args=[node.iter], keywords=[])
        )
        
        # While True loop
        
        # Try-Except block for next()
        try_body = [
            ast.Assign(
                targets=[node.target],
                value=ast.Call(func=ast.Name(id='next', ctx=ast.Load()), args=[ast.Name(id=iter_name, ctx=ast.Load())], keywords=[])
            )
        ]
        
        except_handler = ast.ExceptHandler(
            type=ast.Name(id='StopIteration', ctx=ast.Load()),
            name=None,
            body=[ast.Break()]
        )
        
        try_stmt = ast.Try(
            body=try_body,
            handlers=[except_handler],
            orelse=[],
            finalbody=[]
        )
        
        # Append original body
        loop_body = [try_stmt] + node.body
        
        while_stmt = ast.While(
            test=ast.Constant(value=True),
            body=loop_body,
            orelse=[]
        )
        
        return [assign, while_stmt]
