import os
import torch
import torch.nn as nn
from tqdm import tqdm
import datasets
from model import resnet34, resnet50
import argparse
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, classification_report


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

    embeddings = torch.cat(embeddings, dim=0).numpy()
    labels = torch.cat(labels, dim=0).numpy()
    return embeddings, labels


def main(args):
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
        net = resnet50(num_classes=args.embedding_dim)
    elif args.model == "resnet34":
        net = resnet34(num_classes=args.embedding_dim)

    # 加载训练好的模型权重
    checkpoint_path = args.checkpoint_path
    assert os.path.exists(checkpoint_path), f"Checkpoint not found: {checkpoint_path}"
    net.load_state_dict(torch.load(checkpoint_path, map_location=device))
    net.to(device)
    print(f"Loaded checkpoint from {checkpoint_path}")

    # 提取训练集和测试集的嵌入
    print("Extracting embeddings for training set...")
    train_embeddings, train_labels = extract_embeddings(net, train_loader, device)

    print("Extracting embeddings for test set...")
    test_embeddings, test_labels = extract_embeddings(net, test_loader, device)

    # 使用 k-NN 进行分类
    print("Training k-NN classifier...")
    knn = KNeighborsClassifier(n_neighbors=args.k)
    knn.fit(train_embeddings, train_labels)

    # 在测试集上评估分类器
    print("Evaluating k-NN classifier...")
    test_predictions = knn.predict(test_embeddings)
    accuracy = accuracy_score(test_labels, test_predictions)
    print(f"Test Accuracy: {accuracy:.4f}")

    print("\nClassification Report:")
    print(classification_report(test_labels, test_predictions))

    # 如果需要，可以保存分类结果
    if args.save_results:
        results_path = os.path.join(args.save_path, "classification_results.txt")
        with open(results_path, "w") as f:
            f.write(f"Test Accuracy: {accuracy:.4f}\n")
            f.write("\nClassification Report:\n")
            f.write(classification_report(test_labels, test_predictions))
        print(f"Classification results saved to {results_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Classify using TripletNet embeddings")
    parser.add_argument("--batch_size", type=int, default=64, help="Batch size for data loading")
    parser.add_argument("--model", type=str, default="resnet50", choices=["resnet34", "resnet50"], help="Model type");
    parser.add_argument("--dataset_name", type=str, default="data_sample1000_state5", help="Dataset name")
    parser.add_argument("--dataset_path", type=str, default="data\\strongswan_v1", help="Path to dataset folder")
    parser.add_argument("--checkpoint_path", type=str, default='resnet50_triplet_data_sample1000_state5.pth', help="Path to the trained TripletNet checkpoint")
    parser.add_argument("--embedding_dim", type=int, default=128, help="Dimension of the embedding space")
    parser.add_argument("--k", type=int, default=5, help="Number of neighbors for k-NN")
    parser.add_argument("--save_path", type=str, default="./", help="Path to save classification results")
    parser.add_argument("--save_results", action="store_true", help="Whether to save classification results")
    args = parser.parse_args()
    main(args)
