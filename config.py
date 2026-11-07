import shutil
import urllib.parse
import unicodedata
from pwn import *
import logging

current_user = os.path.expanduser('~')
mkdir_dir = os.path.join(current_user, "tools", "toolchains")
os.makedirs(mkdir_dir, exist_ok=True)
os.makedirs("shellcode_directory", exist_ok=True)

# --- 配置你的交叉编译器路径 ---
CONFIG = {
    "SHELLCODE_DIRECTORY": "shellcode_directory",  # 该目录用于存放生成 shellcode 与中间过程文件
    "ARM_TOOLCHAIN_PATH": None,
    "MIPS_TOOLCHAIN_PATH": None,
    "QEMU_PATH": None,
    "ARM_PATH": None,
    "DOWNLOAD_MIPS_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/mips32/tarballs/mips32--glibc--stable-2024.05-1.tar.xz",
    "DOWNLOAD_MIPSEL_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/mips32el/tarballs/mips32el--glibc--stable-2024.05-1.tar.xz",
    "DOWNLOAD_ARMEB_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/armebv7-eabihf/tarballs/armebv7-eabihf--uclibc--stable-2024.05-1.tar.xz",
    "DOWNLOAD_ARM_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/armv7-eabihf--uclibc--stable-2024.05-1.tar.xz",
    "BAD_BYTES": ['00', '3B', '0a', '0b', '0c', '0d', '20', '09'],
    "TOOLCHAINS_PATH": mkdir_dir,
}



# --- 配置日志记录器 ---
logging.basicConfig(
    level=logging.DEBUG,  # 最低记录级别：DEBUG / INFO / WARNING / ERROR / CRITICAL
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=f"{CONFIG['SHELLCODE_DIRECTORY']}/generate_shellcode.log",
    filemode="a"          # "a" 追加写入，"w" 覆盖写入
)

def check_toolschain(path, arch, endian):
    """
    检查目标目录是否存在。如果不存在，则从指定的URL下载tar.gz文件并解压到该目录。
    该函数依赖于系统已安装 'wget' 和 'tar' 命令。
    """

    print(f"🔎 检查工具链...")
    logging.info(f"🔎 检查工具链...")

    def check_dependencies(path):
        """检查所需的交叉编译工具是否存在于系统中。"""
        tools = ["gcc", "as", "ld", "objcopy"]
        all_found = True
        for tool in tools:
            tool_name = f"{CONFIG[path]}{tool}"
            if not shutil.which(tool_name):
                all_found = False
                print(
                    f"错误: 交叉编译工具 '{tool_name}' 未找到。\n"
                    f"请确保您的 MIPS 交叉编译工具链已安装并在系统 PATH 中。"
                )
            else:
                logging.info(f"✅ 工具链 '{tool_name}' 已存在，无需执行任何操作。")
        return all_found

    # --- 2. 检查目标工具链是否存在 ---
    if check_dependencies(path):
        print(f"✅ 对应交叉编译工具均已下载。")
        logging.info(f"✅ 对应交叉编译工具均已下载。")
    else:
        if arch.lower() == "mips":
            if endian == "little":
                path = CONFIG['DOWNLOAD_MIPSEL_TOOLCHAIN_URL']
            else:
                path = CONFIG['DOWNLOAD_MIPS_TOOLCHAIN_URL']
        else:
            if endian == "little":
                path = CONFIG['DOWNLOAD_ARM_TOOLCHAIN_URL']
            else:
                path = CONFIG['DOWNLOAD_ARMEB_TOOLCHAIN_URL']
        print(f"ℹ️ 目标工具链 '{path}' 不存在，开始执行下载和解压任务...")
        # --- 3. 使用 wget 下载文件 ---
        try:
            filename = os.path.basename(urllib.parse.urlparse(path).path)
            print(f"🔽 正在从 '{path}' 下载文件...")

            # 构建并执行 wget 命令。-O 参数指定输出文件路径。
            with subprocess.Popen(
                    ["wget", path, "-O", f"{CONFIG['TOOLCHAINS_PATH']}/{filename}"],
                    stderr=subprocess.PIPE,
                    bufsize=1,  # 缓冲区大小为1，确保实时性
                    universal_newlines=True  # 以文本模式读取输出
            ) as process:
                # 实时读取并处理 stderr 的每一行
                # 每一行都用回车符 \r 覆盖上一行
                for line in process.stderr:
                    line = line.strip()  # 移除行尾的空白符（包括换行符）
                    if line:  # 确保非空行
                        sys.stdout.write(f"\r{line}")
                        sys.stdout.flush()  # 强制刷新输出，确保立即显示
                # 下载完成后，打印一个空行以确保光标在新的一行
                sys.stdout.write("\n")
                # 检查子进程的退出码
                if process.wait() != 0:
                    raise subprocess.CalledProcessError(
                        process.returncode, process.args
                    )
            print(f"👍 下载成功，文件已保存至: {CONFIG['TOOLCHAINS_PATH']}/{filename}")
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
            print(f"📦 正在将 '{CONFIG['TOOLCHAINS_PATH']}/{filename}' 解压到 '{CONFIG['TOOLCHAINS_PATH']}/'...")
            subprocess.run(["tar", "-xf", f"{CONFIG['TOOLCHAINS_PATH']}/{filename}", "-C", f"{CONFIG['TOOLCHAINS_PATH']}/"],
                           check=True, capture_output=True)
            print(f"\n🎉 任务完成！文件已成功下载并解压到 {CONFIG['TOOLCHAINS_PATH']}/{filename}。")
        except FileNotFoundError:
            print("❌ 错误: 'tar' 命令未找到。请确保它已安装并位于系统的 PATH 环境变量中。")
            return False
        except subprocess.CalledProcessError as e:
            print(f"❌ 使用 tar 解压失败。返回码: {e.returncode}")
            print(f"错误输出:\n{e.stderr.decode('utf-8', errors='ignore')}")
            return False
        return True


class FunctionTruncationSummary:
    """
    一个封装了C语言函数截断属性的类，并提供格式化打印功能。
    """

    def __init__(self):
        """
        初始化类，并加载函数截断属性的总结数据。
        """
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
        """
        计算字符串在终端中的显示宽度，考虑中文字符。
        """
        return sum(2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1 for char in text)

    def print_summary(self):
        """
        打印紧凑型表格。
        """
        if not self.summary_data:
            print("表格数据为空。")
            return

        headers = list(self.summary_data[0].keys())

        # 计算每一列的最大显示宽度
        col_widths = {header: self._get_display_width(header) for header in headers}
        for row in self.summary_data:
            for header in headers:
                content = str(row.get(header, ''))
                col_widths[header] = max(col_widths[header], self._get_display_width(content))

        # 打印表头
        header_line_parts = []
        for header in headers:
            width = col_widths[header]
            padding = width - self._get_display_width(header)
            header_line_parts.append(header + ' ' * padding)
        print(" | ".join(header_line_parts))

        # 打印分隔线
        separator_width = sum(col_widths.values()) + (len(headers) - 1)
        print("-" * separator_width)

        # 打印每一行数据
        for row in self.summary_data:
            row_line_parts = []
            for header in headers:
                content = str(row.get(header, ''))
                width = col_widths[header]
                padding = width - self._get_display_width(content)
                row_line_parts.append(content + ' ' * padding)

            print("|".join(row_line_parts))

