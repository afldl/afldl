// ju.h

#ifdef __cplusplus

extern "C" {

#endif


typedef struct ModelWrapper* ModelHandle;



ModelHandle load_model(const char* path);

void unload_model(ModelHandle model_handle);

void process_input(const char* image_path, unsigned char** data, int* rows, int* cols);

int run_inference(ModelHandle model_handle, unsigned char* data, int rows, int cols);

void save_png(char* data, int row, int col, const char* path);

// for test

void test_hello_world();
void test_model(ModelHandle model_handle);
void test_model_from_png(const char* model_path,const char* img_path);
#ifdef __cplusplus

}

#endif