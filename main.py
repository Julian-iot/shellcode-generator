import argparse
from typing import  Tuple
from pwn import *
from typing import List


from config import CONFIG, check_toolschain
from config import FunctionTruncationSummary
import mips_shellcode_generator, arm_shellcode_generator
from mips_runtime_patching import MipsRuntimePatching
from print_as_py_and_c import *




def check_bad_bytes(binary_data: bytes) -> Tuple[bool, List[str]]:
    """
    检查二进制数据中是否包含配置中指定的任何坏字节。
    这个版本兼容 Python 3.6，使用 typing 模块进行类型注解。

    参数:
    binary_data (bytes): 要检查的二进制数据。

    返回:
    tuple[bool, list[str]]:
        - 第一个元素是布尔值：如果找到了任何坏字节则为 True，否则为 False。
        - 第二个元素是列表：如果找到，则包含所有找到的坏字节（十六进制字符串形式）。
    """
    found_bad_bytes = []
    # 遍历配置中的每个坏字节
    for hex_byte in CONFIG["BAD_BYTES"]:
        # --- 修复代码核心：在转换前去除 '0x' 前缀 ---
        clean_hex_byte = hex_byte.replace('0x', '').replace('0X', '')

        # 确保去除空格（因为您的原始处理逻辑中可能有空格）
        clean_hex_byte = clean_hex_byte.strip()

        if len(clean_hex_byte) == 1:
            clean_hex_byte = '0' + clean_hex_byte
        elif not clean_hex_byte:
            continue  # 跳过空字符串
        # 将十六进制字符串转换为单字节的二进制数据
        try:
            byte_to_check = bytes.fromhex(clean_hex_byte)
        except ValueError:
            print(f"警告: 无效的十六进制字符串 '{clean_hex_byte}'。跳过。")
            continue

        # 检查坏字节是否存在于二进制数据中
        if byte_to_check in binary_data:
            found_bad_bytes.append(clean_hex_byte)

    # 返回检查结果和找到的坏字节列表
    return (len(found_bad_bytes) > 0, found_bad_bytes)

def format_conversion(raw_bad_bytes):
    bad_bytes = [
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
    return bad_bytes

def add_common_arguments(parser):
    """把 ARM 和 MIPS 都要用的公共参数提取出来，避免代码重复"""
    # 端序参数单独放到 mips 下，因为 ARM 默认小端，MIPS 大小端都有需求
    parser.add_argument("-e", "--endian", required=False, choices=['big', 'little'],
                             help="shellcode 字节端序 (big 或 little)。")
    parser.add_argument("-c", "--cmd", required=True, help="要执行的命令。")
    parser.add_argument("-b", "--bad_bytes", nargs="+",
                        help="坏字节列表 (十六进制), default: 0x00,0x3b,0x0a,0x0b,0x0c,0x0d,0x20,0x09")
    parser.add_argument("-x", "--xor_encode", action="store_true", help="对 shellcode 进行XOR编码。")
    parser.add_argument("-v", "--verify", action="store_true", help="编译运行验证 shellcode。")
    parser.add_argument("-sf", "--save_file", action="store_true", help="保存中间文件。")
    parser.add_argument("-fts", "--function_truncation_summary", action="store_true",
                        help="显示函数截断汇总信息表。")




def main():
    # 1. 创建主解析器
    parser = argparse.ArgumentParser(
        description="为一个命令生成 ARM 或 MIPS 架构无 bad 的 shellcode。\n"
                    "注：arm 大端(-e big)默认生成 BE8（指令流小端、数据大端，ARMv6+ 大端 Linux）；\n"
                    "    加 -be32 生成 BE32（指令/数据均大端，ARMv5 及老固件）。\n"
                    "    -v 验证时会自动匹配加载器的 ABI。",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # 2. 创建子命令分类 (arch 会作为存放用户输入的子命令名的变量)
    subparsers = parser.add_subparsers(title="目标架构", dest="arch", required=True, help="选择 CPU 架构")

    # ================= 3. 定义 ARM 分类 =================
    parser_arm = subparsers.add_parser("arm", help="生成 ARM 架构 shellcode")
    add_common_arguments(parser_arm)  # 引入公共参数
    # ARM 专属参数
    parser_arm.add_argument("-be32", "--be32", action="store_true",
                            help="大端时生成 BE32 格式 shellcode(指令与数据都大端)，适用于 ARMv5 及老固件；\n"
                                 "默认不加该参数为 BE8(指令流小端/数据大端)，适用于 ARMv6+ 的大端 Linux。")

    # ================= 4. 定义 MIPS 分类 =================
    parser_mips = subparsers.add_parser("mips", help="生成 MIPS 架构 shellcode")
    add_common_arguments(parser_mips)  # 引入公共参数


    # MIPS 专属参数组
    mips_group = parser_mips.add_argument_group("other")

    # 长短代码生成互斥组（不能同时选）
    mips_exclusive = mips_group.add_mutually_exclusive_group()
    mips_exclusive.add_argument("-short", "--short", action="store_true",
                                help="生成较短的 shellcode，处理过bad_bytes，使用自修复代码方式实现，未用xor编码方式。")
    mips_exclusive.add_argument("-l", "--long_shellcode", action="store_true",
                                help="生成较长的 shellcode。")

    mips_group.add_argument("-rp", "--Mips_Runtime_Patching", nargs=3, metavar=('f32', 'hi16', 'lo16'),
                            help="运行时修补 / 内存修补 (Runtime Patching / In-Memory Patching)，当程序对shellcode某个字节有转换时可使用，如\\x3c转为\\x00导致shellcode无法执行。"
                                 "\nRuntime patching. MODE options: [f32 -28 -32, hi16, lo16]")

    mips_group.add_argument("-s", "--sleep", action="store_true",
                            help="在shellcode前面加上睡眠指令,default 3 秒。")

    args = parser.parse_args()


    # 打印函数截断汇总信息表
    if args.function_truncation_summary:
        summary = FunctionTruncationSummary()
        summary.print_summary()
        return

    if args.bad_bytes:
        CONFIG['BAD_BYTES'] = args.bad_bytes
        is_default_bad_bytes  = False
    else:
        is_default_bad_bytes = True


    # 2. 从配置中获取最终要处理的原始坏字节列表
    # 这行代码负责将各种格式 (如 "00,0a,ff", ["00,0a,ff"], ["00", "0a", "ff"]) 转换为整数列表
    bad_bytes = format_conversion(CONFIG['BAD_BYTES'])

    endian = getattr(args, "endian", None) or "little"
    print_basic_info(args.arch, endian, args.cmd, CONFIG['BAD_BYTES'], is_default_bad_bytes)


    if args.arch.lower() == "mips":
        if endian =="little" :
            CONFIG[
                'MIPS_TOOLCHAIN_PATH'] = f"{CONFIG['TOOLCHAINS_PATH']}/mips32el--glibc--stable-2024.05-1/bin/mipsel-buildroot-linux-gnu-"
            CONFIG['QEMU_PATH'] = "qemu-mipsel"
        else:
            CONFIG[
                'MIPS_TOOLCHAIN_PATH'] = f"{CONFIG['TOOLCHAINS_PATH']}/mips32--glibc--stable-2024.05-1/bin/mips-buildroot-linux-gnu-"
            CONFIG['QEMU_PATH'] = "qemu-mips"
        # --- 1. 检查工具链 ---
        check_toolschain("MIPS_TOOLCHAIN_PATH", args.arch, args.endian)

        if args.Mips_Runtime_Patching:
            number1 = args.Mips_Runtime_Patching[1]
            number2 = args.Mips_Runtime_Patching[2]
            number3 = args.Mips_Runtime_Patching[0]
            patcher = MipsRuntimePatching(number1, number2, number3)
            patcher.apply_patch()
        if args.short:
            msg_short = mips_shellcode_generator.Mips_Generate_short_shellcode(args.cmd, args.endian, args.save_file)
            if args.verify:
                # xor解码器+xor编码后的shellcode合并测试
                mips_shellcode_generator.MipsVerifyShellcode(msg_short.shellcode)
            return
        # --- 2. 生成原始shellcode ---
        if args.cmd:
            print("===" * 30)
            # ---2.1 生成短shellcode---(汇编模板)
            if not args.long_shellcode:
                msg = mips_shellcode_generator.MipsShellcodeGenerator(args.cmd, args.save_file)
            # ---2.2 生成长shellcode---(C + 汇编模板)
            else:
                msg = mips_shellcode_generator.MipsShellcodeGenerator_long(args.cmd, args.arch, args.save_file)
            raw_shellcode_get = msg.raw_shellcode
            print("✅ 生成原始 shellcode 成功 (长度: " + str(len(raw_shellcode_get)) + "字节)")
            print_as_python_bytes(raw_shellcode_get)
        # --- 3. 对 shellcode 进行 XOR 编码 ---
        if args.xor_encode:
            if args.sleep:
                sleep = mips_shellcode_generator.Sleep()
                raw_shellcode_get = (sleep.Sleep_shellcode + raw_shellcode_get)
            else:
                raw_shellcode_get = raw_shellcode_get
            xor_encoder = mips_shellcode_generator.XorEncoder(raw_shellcode_get, endian=args.endian, bad_bytes=bad_bytes)
            print_xor_encoded_info(xor_encoder.attempts, xor_encoder.key, str(len(xor_encoder.xor_encoded_shellcode)))

            print_as_python_bytes(xor_encoder.xor_encoded_shellcode)
            key = xor_encoder.key
            loop_count = len(xor_encoder.xor_encoded_shellcode) // 4
            val_for_loop_count = -(loop_count + 1)

            # --- 4. 生成解码器 ---
            xor_decoder = mips_shellcode_generator.XorDecoder(xor_encoder.xor_encoded_shellcode, key, args.save_file)
            print(
                f"✅  密钥: {hex(xor_decoder.key)}，循环次数: {loop_count}，循环次数值: {val_for_loop_count} -- xor 解码器shellcode (长度: {str(len(xor_decoder.xor_decoded_shellcode))} 字节)")
            # --- 5. 打印解码器shellcode ---
            print_as_python_bytes(xor_decoder.xor_decoded_shellcode)
            # 调用方法生成解码器
            if xor_decoder and xor_encoder:
                merged_shellcode = xor_decoder.xor_decoded_shellcode + xor_encoder.xor_encoded_shellcode
                # 坏字节检查与打印
                found, bad_bytes = check_bad_bytes(merged_shellcode)
                print_bad_bytes_check_info(found, bad_bytes=bad_bytes)

                print(f"✅ xor解码器长度({str(len(xor_decoder.xor_decoded_shellcode))}字节) + xor编码后的shellcode长度({str(len(xor_encoder.xor_encoded_shellcode))}字节) = {str(len(merged_shellcode))} 字节")
                print_as_python_bytes(merged_shellcode)
        else:
            merged_shellcode = raw_shellcode_get
        if args.verify:
            # xor解码器+xor编码后的shellcode合并测试
            mips_shellcode_generator.MipsVerifyShellcode(merged_shellcode)
    elif args.arch.lower() == "arm":
        if endian == "little":
            CONFIG[
                'ARM_TOOLCHAIN_PATH'] = f"{CONFIG['TOOLCHAINS_PATH']}/armv7-eabihf--uclibc--stable-2024.05-1/bin/arm-buildroot-linux-uclibcgnueabihf-"
            CONFIG['ARM_PATH'] = "qemu-arm"
        else:
            CONFIG[
                'ARM_TOOLCHAIN_PATH'] = f"{CONFIG['TOOLCHAINS_PATH']}/armebv7-eabihf--uclibc--stable-2024.05-1/bin/armeb-buildroot-linux-uclibcgnueabihf-"
            CONFIG['ARM_PATH'] = "qemu-armeb"
        # --- 1. 检查工具链 ---
        check_toolschain("ARM_TOOLCHAIN_PATH", args.arch, args.endian)
        print("===" * 30)
        if args.cmd:
            # --- 2. 生成原始shellcode ---
            asg = arm_shellcode_generator.ARMShellcodeGenerator(
                bad_bytes=bad_bytes,
                save_files=args.save_file,
                endian=endian,
                # 大端默认 BE8(ARMv6+ 现代 ABI)，加 -be32 才退回老格式
                be8=(endian == "big" and not args.be32),
            )
            asg._generate_shellcode_from_asm(args.cmd)
            raw_shellcode_get = asg.raw_shellcode
            print("✅ 生成原始 shellcode 成功 (长度: " + str(len(raw_shellcode_get)) + "字节)")
            print_as_python_bytes(raw_shellcode_get)
        if args.cmd and args.xor_encode:
            # --- 3.  XOR 编码 ---
            asg.xorencoder()
            print_xor_encoded_info(asg.attempt, asg.key, str(len(asg.xor_encoded_shellcode)))
            print_as_python_bytes(asg.xor_encoded_shellcode)
            # --- 4. 生成解码器 ---
            asg.xordecoder()
            print(f"✅  密钥: {hex(asg.key)} -- xor 解码器shellcode (长度: " + str(len(asg.xor_decoder_shellcode)) + " 字节)")
            print("")
            print_as_python_bytes(asg.xor_decoder_shellcode)
            merged_shellcode = asg.xor_decoder_shellcode + asg.xor_encoded_shellcode

            # 坏字节检查与打印
            found, bad_bytes = check_bad_bytes(merged_shellcode)
            print_bad_bytes_check_info(found, bad_bytes=bad_bytes)
            print(
                f"✅  xor解码器长度({str(len(asg.xor_decoder_shellcode))}字节) + xor编码后的shellcode长度({str(len(asg.xor_encoded_shellcode))}字节) = {str(len(merged_shellcode))} 字节")

            print_as_python_bytes(merged_shellcode)
        else:
            merged_shellcode = asg.raw_shellcode
        print("=" * 50)
        if args.verify:
            asg.verify_shellcode(merged_shellcode)


if __name__ == "__main__":
    main()
