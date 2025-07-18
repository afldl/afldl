#include "ju.h"
#include "iostream"
#include "opencv2/opencv.hpp"
#include "torch/script.h"







struct ModelWrapper {
    torch::jit::Module model;
};


struct TensorWrapper {
    torch::Tensor tensor;
};



void checkPath(const char* path) {
    std::ifstream in(path);
    if (!in.is_open()) {
        std::cout << "file " << path << " doesn't exist!" << std::endl;
        exit(-1);
    }
}

extern "C" ModelHandle load_model(const char* path) {
    checkPath(path);
    auto* wrapper = new ModelWrapper();
    try {
        wrapper->model = torch::jit::load(path);
    } catch (const c10::Error& e) {
        std::cerr << "Error loading the model from " << path << std::endl;
        delete wrapper;
        return nullptr;
    }
   torch::NoGradGuard no_grad;
    return static_cast<ModelHandle>(wrapper);
}

extern "C" void unload_model(ModelHandle model_handle) {
    auto* wrapper = reinterpret_cast<ModelWrapper*>(model_handle);
    delete wrapper;
}

extern "C" void process_input(const char* image_path, unsigned char** data, int* rows, int* cols) {
    checkPath(image_path);

    cv::Mat img = cv::imread(image_path);
    // std:: cout << img.elemSize() << " ";

    cv::cvtColor(img, img, CV_BGR2GRAY);

    // std:: cout << img.elemSize() << " ";
    // std:: cout << std:: endl;

    
    if(img.empty()) {
        std::cerr << "Image could not be loaded." << std::endl;
        return;
    }
    std:: cout << "image size:" << " ";
    std:: cout << img.rows << " ";
    std:: cout << img.cols << " ";
    std:: cout << img.channels() << " ";
    std:: cout << std:: endl;
    

    *data = img.data;
    *rows = img.rows;
    *cols = img.cols;
}


extern "C" int run_inference(ModelHandle model_handle,  unsigned char* data, int rows, int cols) {
 
    auto* wrapper = reinterpret_cast<ModelWrapper*>(model_handle);
    cv::Mat img(rows, cols, CV_8UC(1), data), fimg;
    img.convertTo(fimg, CV_32F, 1, 0);

    // std::cout << "img:\n"  << std::endl;

    // for(int i = 0; i < img.rows; i++) {
    //     for(int j = 0; j < img.cols; j++) {
    //         std::cout << (int)img.at<uchar>(i, j) << " "; // 打印每个像素的值
    //     }
    //     std::cout << std::endl;
    // }
    // for(int i = 0; i < 1; i++) {
    //     for(int j = 0; j < 10; j++) {
    //         std::cout << (int)img.at<uchar>(i, j) << " "; // 打印每个像素的值
    //     }
    //     std::cout << std::endl;
    // }
    // convert Mat to tensor
    at::Tensor input_tensor = torch::from_blob(
        fimg.data,
        {1, 1, rows, cols},
        torch::kFloat32
    );
    

    std::cout <<  "input shape: "  << input_tensor.sizes() << std::endl; 
// // 打印张量内容
//     std::cout << "Tensor content:\n" << input_tensor << std::endl;
    
    torch::NoGradGuard no_grad;


    torch::Tensor out = wrapper->model({input_tensor}).toTensor();
    
    std::cout <<  "output class: "  << out.item<int>() << std::endl; 

    return out.item<int>();

}


//  test
// test in test(c)
extern "C" void test_model(ModelHandle model_handle) {

    auto* wrapper = reinterpret_cast<ModelWrapper*>(model_handle);

    auto options = torch::TensorOptions().dtype(torch::kFloat32); // ?          ?float32
    torch::Tensor ones_tensor = torch::ones({1, 1, 600, 600}, options);


    std::vector<torch::jit::IValue> inputs;
    inputs.push_back(ones_tensor);

    torch::Tensor out = wrapper->model.forward(inputs).toTensor();

    std::cout <<  "class: "  << out.item<int>() << std::endl; 
    std::cout << std::endl;

}

//  test in main(C++)
void test_model_from_png(const char* model_path,const char* img_path){
    
    std::cout << "test_model_from_png:" << std::endl; 

    cv::Mat img = cv::imread(img_path), gimg, fimg;
    cv::cvtColor(img, gimg, CV_BGR2GRAY);

    std::cout <<  "image size: "  << gimg.rows << " "; 
    std::cout << gimg.cols << " "; 
    std::cout << gimg.channels() << " "; 
    std::cout <<  std::endl; 


    gimg.convertTo(fimg, CV_32F, 1, 0);

    // convert Mat to tensor
    at::Tensor img_tensor = torch::from_blob(
        fimg.data,
        {1, 1, fimg.rows, fimg.cols},
        torch::kFloat32
    );

    // load model
    torch::jit::Module model = torch::jit::load(model_path);

    // torch.no_grad()
    torch::NoGradGuard no_grad;
    
    // forward
    torch::Tensor out = model({img_tensor}).toTensor();

    std::cout <<  "output class: "  << out.item<int>() << std::endl; 

    std::cout << std::endl;
}


// can both  test in (c and c++)
extern "C" void test_hello_world() {
    std::cout << "test_hello_world:" << std::endl;
    std::cout << "Hello, World!" << std::endl;
    std::cout << std::endl;
}



extern "C"  void save_png(char* data, int row, int col, const char* path) {
    // 确保输入数据和路径不为空
    if (data == NULL || path == NULL) {
        fprintf(stderr, "Data pointer or path is null.\n");
        return;
    }

    // 创建一个cv::Mat对象，用于存储图像数据。
    // 注意：这里假设每个像素由一个字节表示（即8位灰度图像）。
    cv::Mat image(row, col, CV_8UC1);

    // 将输入的数据复制到cv::Mat对象中
    memcpy(image.data, data, row * col * sizeof(unsigned char));

    // 保存图像到指定路径的文件
    if (!cv::imwrite(path, image)) {
        fprintf(stderr, "Failed to save image to %s\n", path);
    } else {
        printf("Image successfully saved to %s\n", path);
    }
}