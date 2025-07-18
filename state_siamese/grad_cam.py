import torch
import torch.nn.functional as F
import torchvision.models as models
import torchvision.transforms as transforms
from PIL import Image
import numpy as np
import matplotlib.pyplot as plt

# Grad-CAM 实现
class GradCAM:
    def __init__(self, model, target_layer):
        self.model = model
        self.target_layer = target_layer
        self.gradients = None
        self.activations = None

        # 注册前向传播和反向传播的钩子
        self._register_hooks()

    def _register_hooks(self):
        def forward_hook(module, input, output):
            self.activations = output

        def backward_hook(module, grad_in, grad_out):
            self.gradients = grad_out[0]

        # 在目标层注册钩子
        self.target_layer.register_forward_hook(forward_hook)
        self.target_layer.register_backward_hook(backward_hook)

    def generate_cam(self, input_tensor, target_class=None):
        # 前向传播
        output = self.model(input_tensor)

        # 如果未指定目标类别，则使用预测的类别
        if target_class is None:
            target_class = output.argmax(dim=1).item()

        # 计算目标类别的梯度
        self.model.zero_grad()
        class_score = output[0, target_class]
        class_score.backward()

        # 获取梯度和激活
        gradients = self.gradients.detach()
        activations = self.activations.detach()

        # 计算每个通道的权重
        weights = gradients.mean(dim=(2, 3), keepdim=True)

        # 生成 CAM
        cam = (weights * activations).sum(dim=1, keepdim=True)
        cam = F.relu(cam)  # 只保留正值
        cam = cam.squeeze().cpu().numpy()

        # 归一化到 [0, 1]
        cam = (cam - cam.min()) / (cam.max() - cam.min())
        return cam

# 预处理函数
def preprocess_image(image_path):
    transform = transforms.Compose([
        transforms.ToTensor(),
    ])
    image = Image.open(image_path).convert('RGB')
    input_tensor = transform(image).unsqueeze(0)  # 添加 batch 维度
    return input_tensor, image

# 可视化 Grad-CAM
def visualize_cam(image, cam, alpha=0.5):
    cam = np.uint8(255 * cam)  # 转换为 0-255 的整数
    cam = Image.fromarray(cam).resize(image.size, Image.BILINEAR)
    cam = np.array(cam)

    # 将原图和 CAM 融合
    image = np.array(image)
    heatmap = plt.cm.jet(cam / 255.0)[:, :, :3]  # 使用 jet 颜色映射
    overlay = alpha * heatmap + (1 - alpha) * image / 255.0
    overlay = np.uint8(255 * overlay)

    # 显示结果
    plt.figure(figsize=(8, 8))
    plt.imshow(overlay)
    plt.axis('off')
    plt.show()

# 主函数
if __name__ == "__main__":
    # 加载本地保存的模型
    model = models.resnet50()  # 确保模型结构与保存的权重一致
    model.load_state_dict(torch.load("path_to_your_model.pth", map_location=torch.device('cpu')))
    model.eval()


    # 指定目标层（最后一个卷积层）
    target_layer = model.layer4[2].conv3

    # 创建 Grad-CAM 实例
    grad_cam = GradCAM(model, target_layer)

    # 加载和预处理输入图像
    image_path = "data\strongswan_v1\s0\s0_1.bin"  # 替换为你的图片路径
    input_tensor, image = preprocess_image(image_path)

    # 生成 Grad-CAM
    cam = grad_cam.generate_cam(input_tensor)

    # 可视化 Grad-CAM
    visualize_cam(image, cam)
