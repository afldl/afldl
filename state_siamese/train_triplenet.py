import os
import sys
import wandb  # 添加 W&B
import torch
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm
import datasets
from model import resnet34, resnet50
import argparse  # 用于解析命令行参数
from pytorch_metric_learning.losses import TripletMarginLoss
from pytorch_metric_learning.miners import TripletMarginMiner


def main(args):
    # 初始化 W&B
    wandb.init(
        project="triplet_loss_embedding",  # 替换为你的项目名称
        name=f"{args.model}-embedding-{args.embedding_dim}",  # 运行名称根据模型动态生成
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
        net = resnet50(num_classes=args.embedding_dim)
    elif args.model == "resnet34":
        net = resnet34(num_classes=args.embedding_dim)

    net.to(device)

    # 定义 TripletMarginLoss 和挖掘器
    triplet_loss = TripletMarginLoss(margin=1.0)
    miner = TripletMarginMiner(margin=1.0, type_of_triplets="semi_hard")

    # 定义优化器
    params = [p for p in net.parameters() if p.requires_grad]
    optimizer = optim.Adam(params, lr=args.learning_rate)

    # 初始化训练参数
    save_path = os.path.join(args.save_path, f"{args.model}_triplet_{args.dataset_name}.pth")
    train_steps = len(train_loader)

    # 用于保存验证集上损失最小的模型
    best_val_loss = float("inf")

    for epoch in range(args.epochs):
        # 训练阶段
        net.train()
        running_loss = 0.0
        train_bar = tqdm(train_loader, file=sys.stdout)
        for step, data in enumerate(train_bar):
            images, labels = data
            optimizer.zero_grad()

            # 计算嵌入
            embeddings = net(images.to(device))

            # 挖掘困难三元组
            hard_triplets = miner(embeddings, labels.to(device))

            # 计算 Triplet Loss
            loss = triplet_loss(embeddings, labels.to(device), hard_triplets)
            loss.backward()
            optimizer.step()

            # 统计训练损失
            running_loss += loss.item()
            train_bar.desc = "train epoch[{}/{}] loss:{:.3f}".format(epoch + 1,
                                                                     args.epochs,
                                                                     loss)

        # 记录到 W&B
        wandb.log({
            "train_loss": running_loss / train_steps,
            "epoch": epoch + 1,
        })

        # 验证阶段
        net.eval()
        val_loss = 0.0
        val_steps = len(validate_loader)
        with torch.no_grad():
            val_bar = tqdm(validate_loader, file=sys.stdout)
            for val_data in val_bar:
                val_images, val_labels = val_data

                # 计算嵌入
                embeddings = net(val_images.to(device))

                # 挖掘困难三元组
                hard_triplets = miner(embeddings, val_labels.to(device))

                # 计算 Triplet Loss
                loss = triplet_loss(embeddings, val_labels.to(device), hard_triplets)
                val_loss += loss.item()

                val_bar.desc = "valid epoch[{}/{}]".format(epoch + 1, args.epochs)

        # 计算平均验证损失
        avg_val_loss = val_loss / val_steps

        # 记录验证损失到 W&B
        wandb.log({
            "val_loss": avg_val_loss,
            "epoch": epoch + 1,
        })

        # 保存验证集损失最小的模型
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            torch.save(net.state_dict(), save_path)
            print(f"Saved best model with val_loss: {best_val_loss:.4f}")

    print('Finished Training')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train a ResNet model with Triplet Loss")
    parser.add_argument("--epochs", type=int, default=300, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=64, help="Batch size for training")
    parser.add_argument("--learning_rate", type=float, default=0.0001, help="Learning rate for optimizer")
    parser.add_argument("--model", type=str, default="resnet50", choices=["resnet34", "resnet50"], help="Model type")
    parser.add_argument("--dataset_name", type=str, default="data_sample1000_state5", help="Dataset name")
    parser.add_argument("--dataset_path", type=str, default="data\\strongswan_v1", help="Path to dataset folder")
    parser.add_argument("--save_path", type=str, default="./", help="Path to save the trained model")
    parser.add_argument("--embedding_dim", type=int, default=128, help="Dimension of the embedding space")
    parser.add_argument("--num_classes", type=int, default=5, help="Number of classes in the dataset")
    args = parser.parse_args()
    main(args)
