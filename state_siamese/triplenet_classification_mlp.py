import os
import sys
import json
import wandb  # 用于 W&B 记录

import torch
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm
import datasets
from model import resnet34, resnet50
from sklearn.metrics import confusion_matrix, recall_score
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import argparse  # 用于解析命令行参数


class MLPClassifier(nn.Module):
    """简单的 MLP 分类器"""
    def __init__(self, input_dim, num_classes):
        super(MLPClassifier, self).__init__()
        self.fc = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 1024),
            nn.ReLU(),
            nn.Linear(1024, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, num_classes)
        )

    def forward(self, x):
        return self.fc(x)


def extract_embeddings(model, dataloader, device):
    """
    提取给定数据集的嵌入和标签
    """
    model.eval()
    embeddings = []
    labels = []

    with torch.no_grad():
        for data in tqdm(dataloader, desc="Extracting embeddings"):
            images, batch_labels = data
            images = images.to(device)
            batch_embeddings = model(images)  # 获取嵌入
            embeddings.append(batch_embeddings.cpu())
            labels.append(batch_labels)

    embeddings = torch.cat(embeddings, dim=0)
    labels = torch.cat(labels, dim=0)
    return embeddings, labels


def main(args):
    # 初始化 W&B
    wandb.init(
        project="mlp_classifier_with_triplet_embeddings",  # 替换为你的项目名称
        name=f"MLP-{args.model}-classifier",              # 动态生成运行名称
        config={
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "model": args.model,
            "embedding_dim": args.embedding_dim,
        }
    )

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    print("using {} device.".format(device))

    # 数据集加载
    dataset_path = os.path.join(args.dataset_path, f"{args.dataset_name}.h5")
    train_dataset = datasets.stateMNIST(dataset_path, 'train')
    test_dataset = datasets.stateMNIST(dataset_path, 'test')

    train_loader = torch.utils.data.DataLoader(train_dataset,
                                               batch_size=args.batch_size, shuffle=False, num_workers=4)

    test_loader = torch.utils.data.DataLoader(test_dataset,
                                              batch_size=args.batch_size, shuffle=False, num_workers=4)

    print("using {} images for training, {} images for testing.".format(len(train_dataset), len(test_dataset)))

    # 模型初始化
    if args.model == "resnet50":
        feature_extractor = resnet50(num_classes=args.embedding_dim)
    elif args.model == "resnet34":
        feature_extractor = resnet34(num_classes=args.embedding_dim)

    # 加载训练好的模型权重
    checkpoint_path = args.checkpoint_path
    assert os.path.exists(checkpoint_path), f"Checkpoint not found: {checkpoint_path}"
    feature_extractor.load_state_dict(torch.load(checkpoint_path, map_location=device))
    feature_extractor.to(device)
    feature_extractor.eval()  # 冻结特征提取器
    print(f"Loaded checkpoint from {checkpoint_path}")

    # 提取训练集和测试集的嵌入
    print("Extracting embeddings for training set...")
    train_embeddings, train_labels = extract_embeddings(feature_extractor, train_loader, device)

    print("Extracting embeddings for test set...")
    test_embeddings, test_labels = extract_embeddings(feature_extractor, test_loader, device)

    # 初始化 MLP 分类器
    mlp_classifier = MLPClassifier(input_dim=args.embedding_dim, num_classes=args.num_classes).to(device)
    loss_function = nn.CrossEntropyLoss()
    optimizer = optim.Adam(mlp_classifier.parameters(), lr=args.learning_rate)

    # 训练 MLP 分类器
    best_acc = 0.0
    save_path = os.path.join(args.save_path, "mlp_classifier.pth")
    for epoch in range(args.epochs):
        # 训练阶段
        mlp_classifier.train()
        running_loss = 0.0
        correct_train = 0
        total_train = 0
        train_preds = []
        train_labels_list = []

        for i in range(0, len(train_embeddings), args.batch_size):
            inputs = train_embeddings[i:i + args.batch_size].to(device)
            labels = train_labels[i:i + args.batch_size].to(device)

            optimizer.zero_grad()
            outputs = mlp_classifier(inputs)
            loss = loss_function(outputs, labels)
            loss.backward()
            optimizer.step()

            # 统计训练损失
            running_loss += loss.item()

            # 计算训练准确度
            predict_y = torch.max(outputs, dim=1)[1]
            correct_train += torch.eq(predict_y, labels).sum().item()
            total_train += labels.size(0)

            train_preds.extend(predict_y.cpu().numpy())
            train_labels_list.extend(labels.cpu().numpy())

        train_accuracy = correct_train / total_train
        train_recall = recall_score(train_labels_list, train_preds, average="macro", zero_division=0)

        wandb.log({
            "train_loss": running_loss / len(train_loader),
            "train_accuracy": train_accuracy,
            "train_recall": train_recall,
            "epoch": epoch + 1,
        })

        # 验证阶段
        mlp_classifier.eval()
        acc = 0.0  # 累积准确率
        all_preds = []
        all_labels = []
        with torch.no_grad():
            for i in range(0, len(test_embeddings), args.batch_size):
                inputs = test_embeddings[i:i + args.batch_size].to(device)
                labels = test_labels[i:i + args.batch_size].to(device)

                outputs = mlp_classifier(inputs)
                predict_y = torch.max(outputs, dim=1)[1]
                acc += torch.eq(predict_y, labels).sum().item()

                all_preds.extend(predict_y.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())

        val_accurate = acc / len(test_labels)
        val_recall = recall_score(all_labels, all_preds, average="macro", zero_division=0)
        print('[epoch %d] train_loss: %.3f  train_accuracy: %.3f  train_recall: %.3f  val_accuracy: %.3f  val_recall: %.3f' %
              (epoch + 1, running_loss / len(train_loader), train_accuracy, train_recall, val_accurate, val_recall))

        wandb.log({
            "val_accuracy": val_accurate,
            "val_recall": val_recall,
            "epoch": epoch + 1
        })

        # 保存最优模型
        if val_accurate > best_acc:
            best_acc = val_accurate
            torch.save(mlp_classifier.state_dict(), save_path)

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
    parser = argparse.ArgumentParser(description="Train an MLP classifier on TripletNet embeddings")
    parser.add_argument("--epochs", type=int, default=3000, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=64, help="Batch size for training")
    parser.add_argument("--learning_rate", type=float, default=0.001, help="Learning rate for optimizer")
    parser.add_argument("--model", type=str, default="resnet50", choices=["resnet34", "resnet50"], help="Model type")
    parser.add_argument("--dataset_name", type=str, default="data_sample1000_state10", help="Dataset name")
    parser.add_argument("--dataset_path", type=str, default="data\\strongswan_v1", help="Path to dataset folder")
    parser.add_argument("--checkpoint_path", type=str, default='resnet50_triplet_data_sample1000_state5.pth', help="Path to the trained TripletNet checkpoint")
    parser.add_argument("--embedding_dim", type=int, default=128, help="Dimension of the embedding space")
    parser.add_argument("--num_classes", type=int, default=10, help="Number of classes in the dataset")
    parser.add_argument("--save_path", type=str, default="./", help="Path to save the trained model")
    parser.add_argument("--interval", type=int, default=10, help="Interval for logging confusion matrix")
    args = parser.parse_args()
    main(args)
