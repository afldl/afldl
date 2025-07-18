import os
import sys
import json
import wandb  # 添加 W&B

import torch
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm
import datasets, networks
from model import resnet34, resnet50
from torchvision.datasets import MNIST
from torchvision import transforms
from sklearn.metrics import confusion_matrix, recall_score
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import argparse  # 用于解析命令行参数



def main(args):
    # 初始化 W&B
    wandb.init(
        project=f"{args.protocol}_state_classifier",  # 替换为你的项目名称
        name=f"{args.model}-training_{args.dataset_name}",       # 运行名称根据模型动态生成
        config={
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "model": args.model,
        }
    )

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    print("using {} device.".format(device))

    # 数据集加载
    dataset_path = os.path.join(args.dataset_path, f"{args.dataset_name}.h5")
    train_dataset = datasets.stateMNIST(dataset_path, 'train')
    test_dataset = datasets.stateMNIST(dataset_path, 'test')

    train_num = len(train_dataset)
    val_num = len(test_dataset)

    nw = min([os.cpu_count(), args.batch_size if args.batch_size > 1 else 0, 8])  # number of workers
    print('Using {} dataloader workers every process'.format(nw))

    train_loader = torch.utils.data.DataLoader(train_dataset,
                                               batch_size=args.batch_size, shuffle=True,
                                               num_workers=nw)

    validate_loader = torch.utils.data.DataLoader(test_dataset,
                                                  batch_size=args.batch_size, shuffle=False,
                                                  num_workers=nw)

    print("using {} images for training, {} images for validation.".format(train_num,
                                                                           val_num))
    
    # 模型初始化
    if args.model == "resnet50":
        net = resnet50(num_classes=args.num_classes)
    elif args.model == "resnet34":
        net = resnet34(num_classes=args.num_classes)
    net.to(device)

    # 定义损失函数和优化器
    loss_function = nn.CrossEntropyLoss()
    params = [p for p in net.parameters() if p.requires_grad]
    optimizer = optim.Adam(params, lr=args.learning_rate)

    # 初始化训练参数
    best_acc = 0.0
    save_path = os.path.join(args.save_path, f"{args.model}_{args.dataset_name}.pth")
    train_steps = len(train_loader)

    # 记录到 W&B 的配置
    wandb.config.update({
        "train_size": train_num,
        "val_size": val_num,
        "num_classes": args.num_classes,
    })

    for epoch in range(args.epochs):
        # 训练阶段
        net.train()
        running_loss = 0.0
        correct_train = 0
        total_train = 0
        train_preds = []
        train_labels = []
        train_bar = tqdm(train_loader, file=sys.stdout)
        for step, data in enumerate(train_bar):
            images, labels = data
            optimizer.zero_grad()
            logits = net(images.to(device))
            loss = loss_function(logits, labels.to(device))
            loss.backward()
            optimizer.step()

            # 统计训练损失
            running_loss += loss.item()
            train_bar.desc = "train epoch[{}/{}] loss:{:.3f}".format(epoch + 1,
                                                                     args.epochs,
                                                                     loss)

            # 计算训练准确度
            predict_y = torch.max(logits, dim=1)[1]
            correct_train += torch.eq(predict_y, labels.to(device)).sum().item()
            total_train += labels.size(0)

            # 收集预测值和真实标签
            train_preds.extend(predict_y.cpu().numpy())
            train_labels.extend(labels.cpu().numpy())

            train_accuracy = correct_train / total_train
            train_recall = recall_score(train_labels, train_preds, average="macro", zero_division=0)
        wandb.log({
            "train_loss": loss.item(),
            "train_accuracy": train_accuracy,
            "train_recall": train_recall,
            "epoch": epoch + 1,
        })

        # 验证阶段
        net.eval()
        acc = 0.0  # 累积准确率
        all_preds = []
        all_labels = []
        with torch.no_grad():
            val_bar = tqdm(validate_loader, file=sys.stdout)
            for val_data in val_bar:
                val_images, val_labels = val_data
                outputs = net(val_images.to(device))
                predict_y = torch.max(outputs, dim=1)[1]
                acc += torch.eq(predict_y, val_labels.to(device)).sum().item()

                # 收集所有预测值和真实标签
                all_preds.extend(predict_y.cpu().numpy())
                all_labels.extend(val_labels.cpu().numpy())

                val_bar.desc = "valid epoch[{}/{}]".format(epoch + 1, args.epochs)

        val_accurate = acc / val_num
        val_recall = recall_score(all_labels, all_preds, average="macro", zero_division=0)
        print('[epoch %d] train_loss: %.3f  train_accuracy: %.3f  train_recall: %.3f  val_accuracy: %.3f  val_recall: %.3f' %
              (epoch + 1, running_loss / train_steps, train_accuracy, train_recall, val_accurate, val_recall))

        # 记录验证集准确率到 W&B
        wandb.log({
            "val_accuracy": val_accurate,
            "val_recall": val_recall,
            "epoch": epoch + 1
        })

        # 保存最优模型
        if val_accurate > best_acc:
            best_acc = val_accurate
            torch.save(net.state_dict(), save_path)

        if epoch % args.interval == 0:
            # 混淆矩阵
            cm = confusion_matrix(all_labels, all_preds)
            plot_confusion_matrix(cm, args.num_classes)
            wandb.log({"confusion_matrix": wandb.Image("confusion_matrix.png")})

    print('Finished Training')


def plot_confusion_matrix(cm, num_classes):
    """绘制混淆矩阵并保存为图片"""
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=range(num_classes), yticklabels=range(num_classes))
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.title("Confusion Matrix")
    plt.savefig("confusion_matrix.png")
    plt.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train a ResNet model on stateMNIST dataset")
    parser.add_argument("--epochs", type=int, default=300, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=64, help="Batch size for training")
    parser.add_argument("--learning_rate", type=float, default=0.001, help="Learning rate for optimizer")
    parser.add_argument("--model", type=str, default="resnet50", choices=["resnet34", "resnet50"], help="Model type")
    parser.add_argument("--dataset_name", type=str, default="openssl12_sample100_state6", help="Dataset name")
    parser.add_argument("--dataset_path", type=str, default="data\\openssl12", help="Path to dataset folder")
    parser.add_argument("--save_path", type=str, default="./", help="Path to save the trained model")
    parser.add_argument("--interval", type=int, default=10, help="Interval for logging confusion matrix")
    parser.add_argument("--num_classes", type=int, default=6, help="Number of classes in the dataset")
    parser.add_argument("--protocol", type=str, default="openssl12", help="protocol")
    args = parser.parse_args()
    main(args)


    # parser = argparse.ArgumentParser(description="Train a ResNet model on stateMNIST dataset")
    # parser.add_argument("--epochs", type=int, default=300, help="Number of training epochs")
    # parser.add_argument("--batch_size", type=int, default=64, help="Batch size for training")
    # parser.add_argument("--learning_rate", type=float, default=0.0001, help="Learning rate for optimizer")
    # parser.add_argument("--model", type=str, default="resnet50", choices=["resnet34", "resnet50"], help="Model type")
    # parser.add_argument("--dataset_name", type=str, default="openssl12_sample100_state6", help="Dataset name")
    # parser.add_argument("--dataset_path", type=str, default="data\\openssl12", help="Path to dataset folder")
    # parser.add_argument("--save_path", type=str, default="./", help="Path to save the trained model")
    # parser.add_argument("--interval", type=int, default=10, help="Interval for logging confusion matrix")
    # parser.add_argument("--num_classes", type=int, default=6, help="Number of classes in the dataset")
    # parser.add_argument("--protocol", type=str, default="openssl12", help="protocol")
    # args = parser.parse_args()
    # main(args)