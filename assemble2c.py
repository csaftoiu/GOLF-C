"""Take a golf-cpu binary and output a C file which does the exact same thing."""
import argparse
import sys

sys.path.append("golf-cpu")
from assemble import *


BINARY_OPS = {
    'or': '|',
    'xor': '^',
    'and': '&',
    'add': '+',
    'sub': '-',
    'cmp': '==',
    'neq': '!=',
    'leu': '<',
    'geu': '>',
    'lequ': '<=',
    'gequ': '>=',

    'le': '<',
    'ge': '>',
    'leq': '<=',
    'geq': '>=',

    # shl, shr
}

SIGNED_BINARY_OPS = set(['le', 'ge', 'leq', 'geq'])

def encode_arg(arg):
    if isinstance(arg, Reg):
        return "regs.%s" % arg.reg
    if isinstance(arg, int):
        return str(arg)
    raise NotImplementedError("Arg %s" % (arg,))


def count_pseudo_cycles(instr):
    cycles = 0
    for name, args in translate_pseudo_instr(instr.instr, instr.args):
        cycles += idata.cycle_counts[name]
    return cycles


def assemble2c(lines):
    instructions = preprocess(lines)

    data_segment = b""
    data_offsets = {}

    # Data substitution pass.
    for instr in instructions:
        for i, arg in enumerate(instr.args):
            if isinstance(arg, Data):
                if arg.data not in data_offsets:
                    offset = len(data_segment)
                    data_segment += arg.encode()
                    data_offsets[arg.data] = offset + 0x2000000000000000

                instr.args[i] = data_offsets[arg.data]

    # # Translate pseudo-instructions.
    # instr_nrs = {}
    # n = 0
    # no_pseudo = []
    # for i, instr in enumerate(instructions):
    #     instr_nrs[i] = n
    #     for name, args in translate_pseudo_instr(instr.instr, instr.args):
    #         no_pseudo.append(Instr(instr.debug_line, name, args))
    #         n += 1

    # Label pass.
    labels = {}
    for instr in instructions:
        for i, arg in enumerate(instr.args):
            if isinstance(arg, Label):
                labels[arg.instr_nr] = arg

    print(labels)

    # Encode instructions
    result = []
    with open("prelude.c", "r") as f:
        prelude = f.read()

    prelude = prelude.replace("%%FILLDATA%%", """
#define DATA_LEN %s
uint8_t data[DATA_LEN] = {%s};
""" % (
        len(data_segment),
        ", ".join(map(hex, map(ord, data_segment))),
    ))
    result.append(prelude)

    result.append("""
int main(int argc, char **argv)
{
    init();
""")

    for i, instr in enumerate(instructions):
        cycles = count_pseudo_cycles(instr)
        if i in labels:
            result.append("%s:" % labels[i].name)
            print(labels[i])
        print(instr)

        result.append("    // %s" % lines[instr.debug_line].strip())
        result.append("    cycles += %d;" % (cycles,))

        if instr.instr in BINARY_OPS:
            r, a, b = instr.args
            result.append("    %s = %s%s %s %s%s;" % (
                encode_arg(r),
                "(int64_t)" if instr.instr in SIGNED_BINARY_OPS else "",
                encode_arg(a),
                BINARY_OPS[instr.instr],
                "(int64_t)" if instr.instr in SIGNED_BINARY_OPS else "",
                encode_arg(b),
            ))
        elif instr.instr == "div":
            divres, modres, a, b = instr.args
            result.append("""\
    %s = %s / %s;
    %s = %s %% %s;""" % (
                encode_arg(divres), encode_arg(a), encode_arg(b),
                encode_arg(modres), encode_arg(a), encode_arg(b),
            ))
        elif instr.instr == "mul":
            lowres, hires, a, b = instr.args
            result.append("    mult64to128(%s, %s, &%s, &%s);" % (
                encode_arg(a), encode_arg(b),
                encode_arg(hires), encode_arg(lowres)))
        elif instr.instr == "mov":
            r, a = instr.args
            result.append("    %s = %s;" % (encode_arg(r), encode_arg(a)))
        elif instr.instr == "dec":
            r, = instr.args
            result.append("    %s--;" % (encode_arg(r),))
        elif instr.instr == "jz":
            label, c = instr.args
            result.append("    if (!%s) goto %s;" % (
                encode_arg(c),
                label.name))
        elif instr.instr == "jmp":
            label, = instr.args
            result.append("    goto %s;" % (label.name,))

        elif instr.instr == "call":
            label, = instr.args
            ret_label = "__ret_to_%s" % (instr.debug_line,)
            result.append("""\
    call_stack_regs[call_stack_i] = regs;
    call_stack_returns[call_stack_i] = &&%s;
    call_stack_i++;
    goto %s;
%s:""" % (ret_label, label.name, ret_label))
        elif instr.instr == "ret":
            save_regs = instr.args + ["z"]
            result.append("""\
    {
        struct registers tmp = regs;
        regs = call_stack_regs[call_stack_i - 1];
        %s
        void *ret_addr = call_stack_returns[call_stack_i - 1];
        call_stack_i--;
        goto *ret_addr;
    }""" % "\n    ".join("regs.%s = tmp.%s;" % (r, r) for r in save_regs))

        elif instr.instr == "lw":
            dest, addr = instr.args
            result.append("    %s = load(%s, 8);" % (encode_arg(dest), encode_arg(addr)))
        elif instr.instr == "sw":
            addr, value = instr.args
            result.append("    store(%s, %s, 8);" % (encode_arg(addr), encode_arg(value)))
        elif instr.instr == "pop":
            dest, addr = instr.args
            result.append("    %s -= 8; %s = load(%s, 8);" % (encode_arg(addr), encode_arg(dest), encode_arg(addr)))
        elif instr.instr == "push":
            addr, value = instr.args
            result.append("    store(%s, %s, 8); %s += 8;" % (encode_arg(addr), encode_arg(value), encode_arg(addr)))

        elif instr.instr == "halt":
            if instr.args:
                r = instr.args[0]
            else:
                r = 0

            result.append("    halt(%s);" % encode_arg(r))
        else:
            raise NotImplementedError("Instruction %s" % instr.instr)

    result.append("""
    halt(0);
    return 0;
}
""")

    res = "\n".join(result)
    res = res.replace("#\n", "")
    return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GOLF Assembler to C code")
    parser.add_argument("file", help="assembly file")
    parser.add_argument("-o", metavar="file", dest="c_out", help="output C file")

    args = parser.parse_args()

    with open(args.file, "r") as in_file:
        lines = [l.rstrip() for l in in_file]

    c_code = assemble2c(lines)

    if not args.c_out:
        args.c_out = args.file + ".c"

    with open(args.c_out, "w") as out_file:
        out_file.write(c_code)

