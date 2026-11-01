import os
import subprocess

from config import CONFIG
from print_as_py_and_c import *

class MipsRuntimePatching:
    def __init__(self, number1, number2, number3, save_file=False):
        self.number1 = number1
        self.number2 = number2
        self.number3 = number3
        self.save_file = save_file
    def apply_patch(self):
        if self.number3 == "f32":
            asm_mips = """
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
        elif self.number3 == "lo16":
            # 低位相加绕过过滤\x25
            asm_mips = """
        .section .text
        .set noreorder
        .set noat
        .globl main
        main:
        ori  $t0, $zero, 0x2cf2  # 1. 赋值第一个低 16 位 -> $t0 = 0x00002cf2
        ori  $t1, $zero, 0x3333  # 2. 赋值第二个低 16 位 -> $t1 = 0x00003333
        addu $t0, $t0, $t1       # 3. 两个低 16 位相加   -> $t0 = 0x00006025
        andi $t0, $t0, 0xFFFF    # 4. 强制截断，确保没有进位污染高位（安全保险）

        lui  $at, 0x018d         # 5. 加载高 16 位       -> $at = 0x018d0000
        addu $t0, $t0, $at      # 6. 将低位加法结果与高位合并 -> $t0 = 0x018d6025
        sw   $t0,{number1}($sp)
        """
        # 高位相加绕过过滤\x25
        elif self.number3 == "hi16":
            asm_mips = """
        .section .text
        .set noreorder
        .set noat
        .globl main
        main:
        lui  $t0, 0x13f7  # 1. 赋值第一个高 16 位 -> $t0 = 0x13f70000
        lui  $t1, 0x1111  # 2. 赋值第二个高 16 位 -> $t0 = 0x11110000
        addu $t0, $t0, $t1       # 3. 两个低 16 位相加   -> 0x25080000

        ori  $at, $zero, 0xffff         # 5. 加载低 16 位  -> 0x0000ffff
        addu $t0, $t0, $at      # 6. 将低位加法结果与高位合并 -> 0x2508ffff
        sw   $t0,{number1}($sp)
            """


        # 确保输出目录存在
        try:
            asm_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_test_shellcode.s")
            obj_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_test_shellcode.o")
            bin_file_path = os.path.join(CONFIG["SHELLCODE_DIRECTORY"], "mips_test_shellcode.bin")
            temp_asm = asm_mips.format(number1=self.number1, number2=self.number2)
            with open(asm_file_path, "w") as f:
                f.write(temp_asm)

            subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}as", "-o", obj_file_path, asm_file_path], check=True)
            result = subprocess.run([f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objdump", "-d", obj_file_path],
                                    capture_output=True,
                                    text=True, check=True)
            print(result.stdout.strip())
            print("------------------------------\n")
            subprocess.run(
                [f"{CONFIG['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "--only-section=.text", obj_file_path,
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
                f"[!] 错误: MIPS 交叉编译工具链未找到, 请检查 CONFIG['MIPS_TOOLCHAIN_PATH'] 的设置: '{CONFIG['MIPS_TOOLCHAIN_PATH']}'")
        except subprocess.CalledProcessError as e:
            print(f"[!] 编译失败: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                print(f"错误详情: {e.stderr.decode('utf-8', 'ignore')}")
        except Exception as e:
            print(f"[!] 发生错误: {e}")
        finally:
            files_to_clean = [asm_file_path, obj_file_path, bin_file_path]
            if not self.save_file:
                for f in files_to_clean:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print_process_file_path(None, asm_file_path, obj_file_path, None, bin_file_path)