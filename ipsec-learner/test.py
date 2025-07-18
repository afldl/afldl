import argparse

def main():
    # 创建 ArgumentParser 对象
    parser = argparse.ArgumentParser(description="Process some configuration.")

    # 添加 -S 开关参数
    parser.add_argument('-S', action='store_true', help='Enable special operation mode.')

    # 添加配置文件参数
    parser.add_argument('config', type=str, help='The path to the configuration file.')

    # 解析命令行参数
    args = parser.parse_args()

    # 打印解析结果
    print(f"Config file: {args.config}")
    if args.S:
        print("Special operation mode is enabled.")
    else:
        print("Normal operation mode.")

if __name__ == '__main__':
    main()