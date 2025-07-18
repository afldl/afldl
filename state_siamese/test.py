from PIL import Image

def data2fig(data):
    width, length = 300, 300
    total_pixels = width * length
    
    # 初始化一个空列表用于存储处理后的像素值
    pixel_data = []
    
    # 遍历输入的二进制数据列表，提取每个字节作为一个像素点
    for item in data:
        # 将每个数据项转换为bytearray以便于迭代
        byte_array = bytearray(item)
        # 添加到pixel_data中
        pixel_data.extend(byte_array)
        
        # 如果在处理过程中已经收集了足够的像素，则停止
        if len(pixel_data) >= total_pixels:
            break
    
    # 如果数据不足，则用0填充至所需的总像素数量
    if len(pixel_data) < total_pixels:
        pixel_data.extend([0] * (total_pixels - len(pixel_data)))
    
    # 确保我们只使用正好需要的像素数
    pixel_data = pixel_data[:total_pixels]
    
    # 创建一个新的300x300灰度图像
    img = Image.new('L', (width, length))
    
    # 将数据映射到图像中
    img.putdata(pixel_data)
    
    return img

# 示例用法
if __name__ == "__main__":
    # 假设我们有一个二进制数据列表作为示例
    example_data = [b'\xFF\x00\xFF'] * 30000  # 每个元素有多个字节，这里生成了一些示例数据
    
    image = data2fig(example_data)
    image.show()  # 显示图像
    # 或者保存图像
    # image.save('output_image.png')