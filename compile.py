import sys
import os
import argparse
import re

from pycparser import c_parser, c_ast, c_generator, preprocess_file


STDLIB = """\
putchar:     # int putchar(int a)
    pop a, z   # int a
    sw -1, a
    push z, 0  # return 0
    ret
"""


class ObjectScope(object):
    def __init__(self):
        self.register_variables = {}

    def assign_variable(self, varname, register):
        if varname in self.register_variables:
            raise ValueError("Duplicate var %s in scope" % (varname,))

        self.register_variables[varname] = register

    def free_variable(self, varname):
        if varname not in self.register_variables:
            raise ValueError("Freeing non-existent variable %s" % (varname,))

        del self.register_variables[varname]


class RegisterScope(object):
    def __init__(self):
        self.free_registers = set("abcdefghijklmnopqrstuvwxy")
        self.dest_registers = []
        self.object_scopes = []

        self.enter_new_object_scope()

    # Scope functions
    def cur_object_scope(self):
        return self.object_scopes[-1]

    def enter_new_object_scope(self):
        self.object_scopes.append(ObjectScope())

    def exit_object_scope(self):
        del self.object_scopes[-1]

    def get_var_register(self, varname):
        for obj_scope in reversed(self.object_scopes):
            if varname in obj_scope.register_variables:
                return obj_scope.register_variables[varname]

        raise ValueError("Invalid variable name: %s" % (varname,))

    # Register allocation
    def num_free_registers(self):
        return len(self.free_registers)

    def allocate_register(self):
        if not self.free_registers:
            raise ValueError("No more free registers")

        r = self.free_registers.pop()
        return r

    def free_register(self, r):
        if r in self.free_registers:
            raise ValueError("Register '%s' is already free" % (r,))
        self.free_registers.add(r)

    # Dest register mappings
    def push_dest_register(self, r=None):
        if r is None:
            r = self.allocate_register()

        if r in self.free_registers:
            raise ValueError("Can't push free register as dest register")

        self.dest_registers.append(r)
        return r

    def pop_dest_register(self, free=True):
        res = self.dest_registers.pop()
        if free:
            self.free_register(res)
        return res

    def cur_dest_register(self):
        if not self.dest_registers:
            raise ValueError("No dest registers")
        return self.dest_registers[-1]


class CompilerVisitor(c_ast.NodeVisitor):
    PASS_THROUGH_NODES = ["Compound"]

    REF_INDENT_NODES = ["Return", "BinaryOp", "Decl", "ID"]

    BINARY_OPS = {
        '|': 'or',
        '^': 'xor',
        '&': 'and',
        '<<': 'shl',
        '>>': 'shr',
        '+': 'add',
        '-': 'sub',
        '==': 'cmp',
        '!=': 'neq',
        '<': ['le', 'leu'],
        '>': ['ge', 'geu'],
        '<=': ['leq', 'lequ'],
        '>=': ['geq', 'gequ'],
    }

    def __init__(self, filename):
        self.filename = filename

        self.assembly = []

        self.labels = set()
        self.calls = set()

        self.scopes = []

        self.enter_new_scope()

        self.indent = 4

        self.label_counter = 0

        self.func_types = {
            'putchar': ('int', ['int']),
            'getchar': ('int', ['int']),
        }

    # Generation functions
    def increase_indent(self):
        self.indent += 1

    def decrease_indent(self):
        self.indent -= 1

    def gen_newline(self):
        self.assembly.append("")

    def gen_comment(self, comment):
        self.assembly.append("%s# %s" % (" "*self.indent, comment,))

    def unique_label(self, hint):
        name = None

        while not name or name in self.labels:
            name = "__%s_%s_%s" % (self.filename, hint, self.label_counter)
            name = re.sub("[^a-zA-Z0-9_]", "_", name)
            self.label_counter += 1

        return name

    def gen_label(self, name):
        if name in self.labels:
            raise ValueError("Duplicate label: %s" % (name,))

        self.assembly.append("%s:" % (name,))
        self.labels.add(name)

    def gen_instr(self, name, *operands):
        self.assembly.append("%s%s %s" % (" "*self.indent, name, ", ".join(map(str, operands))))

    def gen_push(self, a, b):
        self.gen_instr("push", a, b)

    def gen_push_stack(self, r):
        self.gen_push("z", r)

    def gen_pop(self, a, b):
        self.gen_instr("pop", a, b)

    def gen_pop_stack(self, r):
        self.gen_pop(r, "z")

    def gen_binary_op(self, op, l, r):
        if op in "/%*":
            result = self.cur_scope().cur_dest_register()
            ignore = self.cur_scope().push_dest_register()
            if op == "/":
                self.gen_instr("div", result, ignore, l, r)
            elif op == "%":
                self.gen_instr("div", ignore, result, l, r)
            elif op == "*":
                self.gen_instr("mul", result, ignore, l, r)
            self.cur_scope().pop_dest_register()
            return

        if op not in self.BINARY_OPS:
            raise NotImplementedError("Binary op %s" % (op,))

        which = self.BINARY_OPS[op]
        if isinstance(which, list):
            # TODO: handle signed/unsigned ops
            which = which[0]

        self.gen_instr(which, self.cur_scope().cur_dest_register(), l, r)

    def gen_mov(self, r, a):
        self.gen_instr("mov", r, a)

    def gen_ret(self, *keeps):
        self.gen_instr("ret", *keeps)

    def gen_call(self, label):
        self.gen_instr("call", label)
        self.calls.add(label)

    def gen_halt(self, r=None):
        operands = [r] if r else []
        self.gen_instr("halt", *operands)

    def gen_main_prelude(self):
        self.gen_call("main")
        self.gen_pop_stack("a")
        self.gen_halt("a")
        self.gen_newline()

    def gen_source_ref(self, node):
        self.gen_comment("%s: %s" % (node.coord.line, c_generator.CGenerator().visit(node)))

    def gen_jz(self, label, r):
        self.gen_instr("jz", label, r)

    def gen_jmp(self, label):
        self.gen_instr("jmp", label)
        self.calls.add(label)

# Semantic functions
    def enter_new_scope(self):
        self.scopes.append(RegisterScope())

    def exit_scope(self):
        del self.scopes[-1]

    def cur_scope(self):
        return self.scopes[-1]

    # Visit functions
    def visit_ID(self, node):
        # move variable into dest
        self.gen_mov(self.cur_scope().cur_dest_register(), self.cur_scope().get_var_register(node.name))

    def visit_Decl(self, node):
        if node.quals:
            raise NotImplementedError("Decl with qualifiers")
        if node.funcspec:
            raise NotImplementedError("Decl with funcspec")
        if node.storage:
            raise NotImplementedError("Decl with storage")
        if node.bitsize:
            raise NotImplementedError("Decl with bitsize")

        # check the decl type
        self.visit(node.type)

        # store it in a register
        scope = self.cur_scope()
        var_register = scope.allocate_register()
        scope.cur_object_scope().assign_variable(node.name, var_register)

        if node.init:
            scope.push_dest_register(var_register)
            self.visit(node.init)
            scope.pop_dest_register(free=False)

    def visit_TypeDecl(self, node):
        if node.quals:
            raise NotImplementedError("Type with qualifiers")

        if node.type.__class__.__name__ != "IdentifierType":
            raise NotImplementedError("Complex return types")

        if node.type.names != ['int']:
            raise NotImplementedError("Non-int type")

    def visit_Constant(self, node):
        """Place the constant into the current destination register"""
        if node.type == "int":
            self.gen_mov(self.cur_scope().cur_dest_register(), node.value)
        elif node.type == "char":
            self.gen_mov(self.cur_scope().cur_dest_register(), ord(eval(node.value)))
        else:
            raise NotImplementedError("Constant of type %s" % (node.type,))

    def visit_BinaryOp(self, node):
        """Place the result of the op into the current destination register"""
        left = self.cur_scope().push_dest_register()
        self.visit(node.left)

        right = self.cur_scope().push_dest_register()
        self.visit(node.right)

        self.cur_scope().pop_dest_register()
        self.cur_scope().pop_dest_register()

        self.gen_binary_op(node.op, left, right)

    def visit_Assignment(self, node):
        self.gen_source_ref(node)

        if not isinstance(node.lvalue, c_ast.ID):
            raise ValueError("Assignment to non-ID %s" % (node.lvalue,))

        value = self.cur_scope().push_dest_register()
        self.visit(node.rvalue)
        self.gen_mov(self.cur_scope().get_var_register(node.lvalue.name), value)
        self.cur_scope().pop_dest_register()

    def visit_If(self, node):
        cond = self.cur_scope().push_dest_register()
        self.visit(node.cond)
        else_label = self.unique_label("else")
        self.gen_jz(else_label, cond)
        self.cur_scope().pop_dest_register()

        if node.iftrue:
            self.visit(node.iftrue)
        self.gen_label(else_label)
        if node.iffalse:
            self.visit(node.iffalse)

    def visit_Return(self, node):
        dest = self.cur_scope().push_dest_register()

        self.visit(node.expr)

        self.gen_push_stack(dest)
        self.cur_scope().pop_dest_register()
        self.gen_ret()

    def visit_FuncDef(self, node):
        # entry point
        self.gen_label(node.decl.name)

        # unpack arguments
        func_decl = node.decl.type
        if func_decl.args:
            raise NotImplementedError("Function with arguments")

        # semantic check return type
        ret_type = func_decl.type
        self.visit(ret_type)

        # process body. TODO: enforce proper return type
        self.enter_new_scope()
        self.visit(node.body)
        self.exit_scope()
        self.gen_ret()

    def visit_FuncCall(self, node):
        if not isinstance(node.name, c_ast.ID):
            raise NotImplementedError("Indirect function calls")

        if node.name.name not in self.func_types:
            raise ValueError("Call to unknown function %s" % (node.name,))

        ret_val, arg_types = self.func_types[node.name.name]
        if ret_val not in ("int", "void"):
            raise NotImplementedError("Non-int/void return value")

        if len(arg_types) != len(node.args.exprs):
            raise ValueError("%s expected %d arguments, got %d" % (
                node.name, len(arg_types), len(node.args.exprs)))

        # TODO: check arg types
        # push first args first
        for expr in node.args.exprs:
            arg = self.cur_scope().push_dest_register()
            self.visit(expr)
            self.gen_push_stack(arg)
            self.cur_scope().pop_dest_register()
        # call
        self.gen_call(node.name.name)
        if ret_val == "int":
            # pop return value
            # TODO: figure out dest register for function call statements
            waste = None
            if not self.cur_scope().dest_registers:
                waste = self.cur_scope().push_dest_register()

            self.gen_pop_stack(self.cur_scope().cur_dest_register())

            if waste:
                self.cur_scope().pop_dest_register()

        elif ret_val == "void":
            pass
        else:
            pass

    def visit_Label(self, node):
        self.gen_label(node.name)
        if node.stmt:
            self.visit(node.stmt)

    def visit_Goto(self, node):
        self.gen_jmp(node.name)

    def visit_FileAST(self, node):
        self.gen_main_prelude()

        for ext in node.ext:
            self.visit(ext)

        self.gen_newline()
        self.assembly.append(STDLIB)
        self.gen_newline()

    def visit(self, node):
        if node.__class__.__name__ in self.REF_INDENT_NODES:
            self.gen_source_ref(node)
            self.increase_indent()

        c_ast.NodeVisitor.visit(self, node)

        if node.__class__.__name__ in self.REF_INDENT_NODES:
            self.decrease_indent()

    def generic_visit(self, node):
        if node.__class__.__name__ in self.PASS_THROUGH_NODES:
            return c_ast.NodeVisitor.generic_visit(self, node)

        node.show()
        print node.children()

        raise NotImplementedError("Compile %s" % node.__class__.__name__)


def compile(filename, source):
    parser = c_parser.CParser()
    ast = parser.parse(source)

    v = CompilerVisitor(filename)
    v.visit(ast)

    if v.calls - v.labels:
        print "Warning: No labels for calls [%s]" % ", ".join(v.calls - v.labels)

    return "\n".join(v.assembly)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GOLF C compiler.")
    parser.add_argument("file", help="source file")
    parser.add_argument("-o", metavar="file", dest="binary_out", help="output file")
    parser.add_argument("-S", metavar="file", dest="assembly_out",
                        help="also produce assembly to the given file")

    args = parser.parse_args()

    source = preprocess_file(args.file)

    #with open(args.file) as in_file:
    #    source = in_file.read()

    assembly = compile(args.file, source)

    if args.assembly_out:
        with open(args.assembly_out, "wb") as out_file:
            out_file.write(assembly)
    else:
        print "Warning: binary output not implemented yet"
