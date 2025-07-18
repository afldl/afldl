import os,glob

dir = r"cache2"


def dot2pdf(path):
    os.system(f'dot -Tpdf -O {path}')
    os.system(f'dot -Tsvg -O {path}')



def recursive_listdir(path):

    files = os.listdir(path)
    for file in files:
        file_path = os.path.join(path, file)

        if os.path.isfile(file_path) and file_path.split('.')[-1] == 'dot':
            # print(file)
            print(file_path)
            dot2pdf(file_path)



        elif os.path.isdir(file_path):
          recursive_listdir(file_path)



recursive_listdir(r'cache2')

