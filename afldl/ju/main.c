#include "ju.h"


// ./main /home/ubuntu/experiments/in-tls/model.pt ../s0.png
int main(int argc, char *argv[]) {

    test_hello_world();
    test_model_from_png(argv[1], argv[2]);
    return 0;

}


