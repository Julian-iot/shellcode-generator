import json
import string

def print_as_c_string(data, var_name="shellcode"):
    """
    将二进制数据打印成C语言字符串字面量的格式。
    例如: "\xde\xad\xbe\xef"
    """
    print(f"char {var_name}[] =")
    # 每4个字节为一组，生成一行字符串
    for i in range(0, len(data), 4):
        # 获取当前行的数据块
        chunk = data[i:i + 4]
        # 将每个字节格式化为 \xHH 的形式
        hex_string = "".join([f"\\x{byte:02x}" for byte in chunk])
        # 打印被双引号包围的字符串
        print(f'    "{hex_string}"')
    print(";")


def print_as_python_bytes(data, var_name="shellcode", line_len=20):
    """
    将二进制数据打印成Python中通过 += 逐行构建字节字符串的格式。
    例如: buf += b"\\xde\\xad\\xbe\\xef"
    """
    # 首先打印初始化行
    print(f'{var_name} = b""')

    # 每次处理 line_len 个字节
    for i in range(0, len(data), line_len):
        # 获取当前行的数据块
        chunk = data[i:i + line_len]
        # 将每个字节格式化为 \xHH 的形式
        hex_string = "".join([f"\\x{byte:02x}" for byte in chunk])
        # 打印 "buf += b'...'" 格式的字符串
        print(f'{var_name} += b"{hex_string}"')
    print("\n")


def print_basic_info(arch: string, endian: string, cmd: string, bad_bytes: list, is_default_bad_bytes: bool
                     ):
    basic_info = {
        "architecture": arch,
        "endianness": endian,
        "command": cmd,
        "bad_bytes": bad_bytes,
        "using_default_bad_bytes": is_default_bad_bytes
    }
    json_output = json.dumps(basic_info, ensure_ascii=False)
    print("📋 基础信息:\n"+json_output)

def print_bad_bytes_check_info(found: bool, bad_bytes: list ):
    info = {"Find the bad byte": found,
            "bad byte list": bad_bytes,
    }
    json_output = json.dumps(info, ensure_ascii=False)
    print("🔎 检查解码器坏字节:\n" + json_output)

def print_xor_encoded_info(number: int, key, xor_shellcode_len):
    status = "Success" if number else "Failure"
    info = {"xor encoding": status,
            "Number of attempts": number,
            "Security Key": hex(key),
            "Length of XOR-encoded shellcode": xor_shellcode_len
    }
    json_output = json.dumps(info, ensure_ascii=False)
    print("🔎 shellcode xor encoding info: " + json_output)

def print_process_file_path(c_file_path, asm_file_path, obj_file_path, elf_file_path=None, bin_file_path=None):
    print(f" [+] 过程文件已保存:")

    print(f"  - C 源码: {c_file_path}")
    print(f"  - 汇编源码 (Assembly): {asm_file_path}")
    print(f"  - 目标文件 (Object): {obj_file_path}")
    print(f"  - 链接文件 (ELF): {elf_file_path}")
    print(f"  - 原始机器码 (Raw): {bin_file_path}")