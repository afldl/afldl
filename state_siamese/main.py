# %%
# %%
import torch
from torch.optim import lr_scheduler
import torch.optim as optim
from torch.autograd import Variable

from trainer import fit
import numpy as np
cuda = torch.cuda.is_available()

# %matplotlib inline
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

# 使用 matplotlib 的 colormap 来生成更多的颜色
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

# 扩展后的类别名称
mnist_classes = [str(i) for i in range(10)]  # 类别名称为 '0' 到 '23'



# 定义一个包含24种颜色的颜色列表
colors = list(mcolors.TABLEAU_COLORS.values())[:10]  # 先取前10个默认颜色
additional_colors = plt.cm.tab20(np.linspace(0, 1, 14))  # 从 tab20 colormap 中获取14个新颜色
colors.extend([mcolors.rgb2hex(color) for color in additional_colors])  # 将新颜色转换为十六进制格式并添加到列表中

# 确保我们有24个颜色
assert len(colors) == 24, "颜色数量不匹配"

# # 打印结果以确认
# print("Classes:", mnist_classes)
# print("Colors:", colors)


# %%
def plot_embeddings(embeddings, targets, xlim=None, ylim=None):
    plt.figure(figsize=(10,10))
    for i in range(10):
        inds = np.where(targets==i)[0]
        plt.scatter(embeddings[inds,0], embeddings[inds,1], alpha=0.5, color=colors[i])
    if xlim:
        plt.xlim(xlim[0], xlim[1])
    if ylim:
        plt.ylim(ylim[0], ylim[1])
    plt.legend(mnist_classes)

def extract_embeddings(dataloader, model):
    with torch.no_grad():
        model.eval()
        embeddings = np.zeros((len(dataloader.dataset), 2))
        labels = np.zeros(len(dataloader.dataset))
        k = 0
        for images, target in dataloader:
            if cuda:
                images = images.cuda()
            embeddings[k:k+len(images)] = model.get_embedding(images).data.cpu().numpy()
            labels[k:k+len(images)] = target.numpy()
            k += len(images)
    return embeddings, labels


# %%

import datasets

from torchvision.datasets import MNIST
from torchvision import transforms


if __name__ == '__main__':


    n_classes = 10
    # dataset_path = 'data\strongswan_v1\data.h5'
    # train_dataset = datasets.stateMNIST(dataset_path, 'train')
    # test_dataset = datasets.stateMNIST(dataset_path, 'test')


    mean, std = 0.1307, 0.3081

    train_dataset = MNIST('./data/MNIST', train=True, download=True,
                                transform=transforms.Compose([
                                    transforms.Resize((300, 300)),
                                    transforms.ToTensor(),
                                    transforms.Normalize((mean,), (std,))
                                ]))
    test_dataset = MNIST('./data/MNIST', train=False, download=True,
                                transform=transforms.Compose([
                                    transforms.Resize((300, 300)),
                                    transforms.ToTensor(),
                                    
                                    transforms.Normalize((mean,), (std,))
                                ]))



    # Set up data loaders
    batch_size = 16 
    kwargs = {'num_workers': 8, 'pin_memory': True} if cuda else {}
    train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=batch_size, shuffle=True, **kwargs)
    test_loader = torch.utils.data.DataLoader(test_dataset, batch_size=batch_size, shuffle=False, **kwargs)

    # Set up the network and training parameters
    from networks import convnextv2_base
    from metrics import AccumulatedAccuracyMetric


    model = convnextv2_base(n_classes,in_chans=1)
    if cuda:
        model.cuda()
    loss_fn = torch.nn.CrossEntropyLoss()
    lr = 1e-3
    optimizer = optim.Adam(model.parameters(), lr=lr)
    scheduler = lr_scheduler.StepLR(optimizer, 8, gamma=0.1, last_epoch=-1)
    n_epochs = 200
    log_interval = 50

    # %%
    fit(train_loader, test_loader, model, loss_fn, optimizer, scheduler, n_epochs, cuda, log_interval, metrics=[AccumulatedAccuracyMetric()])


