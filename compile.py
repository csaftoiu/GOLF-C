import sys
import os
import argparse

from pycparser import c_parser, c_ast


PRELUDE = ["    call main", "    pop a, z", "    halt 0"]


class Scope(object):
    def __init__(self):
        self.free_registers = set("abcdefghijklmnopqrstuvwxy")

        self.dest_registers = []

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

    BINARY_OPS = {
        '|': 'or', '^': 'xor', '&': 'and',
        '<<': 'shl', '>>': 'shr',
        '+': 'add', '-': 'sub',
        '==': 'cmp', '!=': 'neq',
        '<': ['le', 'leu'], '>': ['ge', 'geu'], '<=': ['leq', 'lequ'], '>=': ['geq', 'gequ'],
    }

    def __init__(self):
        self.assembly = []
        self.assembly.extend(PRELUDE)
        self.assembly.append("")

        self.labels = set()

        self.scopes = [Scope()]

    # Generation functions
    def gen_newline(self):
        self.assembly.append("")

    def gen_label(self, name):
        if name in self.labels:
            raise ValueError("Duplicate label: %s" % (name,))

        self.assembly.append("%s:" % (name,))
        self.labels.add(name)

    def gen_instr(self, name, *operands):
        self.assembly.append("    %s %s" % (name, ", ".join(map(str, operands))))

    def gen_push(self, a, b):
        self.gen_instr("push", a, b)

    def gen_push_stack(self, r):
        self.gen_push("z", r)

    def gen_binary_op(self, op, l, r):
        if op not in self.BINARY_OPS:
            raise NotImplementedError("Binary op %s" % (op,))

        self.gen_instr(self.BINARY_OPS[op], self.cur_scope().cur_dest_register(), l, r)

    def gen_assign(self, r, a):
        self.assembly.append("    mov %s, %s" % (r, a))

    def gen_ret(self, *keeps):
        self.gen_instr("ret", *keeps)

    # Semantic functions
    def enter_new_scope(self):
        self.scopes.append(Scope())

    def exit_scope(self):
        del self.scopes[-1]

    def cur_scope(self):
        return self.scopes[-1]

    # Visit functions
    def visit_TypeDecl(self, node):
        if node.quals:
            raise NotImplementedError("Type with qualifiers")

        if node.type.__class__.__name__ != "IdentifierType":
            raise NotImplementedError("Complex return types")

        if node.type.names != ['int']:
            raise NotImplementedError("Non-int type")

    def visit_Constant(self, node):
        """Place the constant into the current destination register"""
        if node.type != "int":
            raise NotImplementedError("Non-int constant")

        self.gen_assign(self.cur_scope().cur_dest_register(), node.value)

    def visit_BinaryOp(self, node):
        """Place the result of the op into the current destination register"""
        left = self.cur_scope().push_dest_register()
        self.visit(node.left)

        right = self.cur_scope().push_dest_register()
        self.visit(node.right)

        self.cur_scope().pop_dest_register()
        self.cur_scope().pop_dest_register()

        self.gen_binary_op(node.op, left, right)

    def visit_Return(self, node):
        dest = self.cur_scope().push_dest_register()

        self.visit(node.expr)

        self.gen_push_stack(dest)
        self.cur_scope().pop_dest_register()

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

    def visit_FileAST(self, node):
        for ext in node.ext:
            self.visit(ext)

        self.gen_newline()

    def generic_visit(self, node):
        if node.__class__.__name__ in self.PASS_THROUGH_NODES:
            return c_ast.NodeVisitor.generic_visit(self, node)

        node.show()
        print node.children()

        raise NotImplementedError("Compile %s" % node.__class__.__name__)


def compile(source):
    parser = c_parser.CParser()
    ast = parser.parse(source)

    v = CompilerVisitor()
    v.visit(ast)

    return "\n".join(v.assembly)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GOLF C compiler.")
    parser.add_argument("file", help="source file")
    parser.add_argument("-o", metavar="file", help="output file")
    parser.add_argument("-S", dest="output_assembly", action="store_true",
                        help="don't produce binary, produce assembly to a file with a .s extension")

    args = parser.parse_args()

    if not args.output_assembly:
        print "Can only output assembly, not binaries"
        sys.exit(1)

    if args.o is None: args.o = os.path.splitext(args.file)[0] + (".s" if args.output_assembly else ".bin")

    with open(args.file) as in_file:
        source = in_file.read()

    assembly = compile(source)

    with open(args.o, "wb") as out_file:
        out_file.write(assembly)
