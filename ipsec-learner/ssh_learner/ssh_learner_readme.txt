python2需要加几个包
首先安装pip2
yum install python-pip
然后整一下这个
sudo yum install python-devel
之后装包
pip2 install ecdsa
pip2 install pycrypto



模型学习
python2 learner_start_up.py -t 127.0.0.1 -P 22 -u root -p pipilu123456 -o ./output -oj ./output.json
-t 目标IP
-P是目标端口
-u 是ssh用户名
-p 是ssh口令
-o 学习输出的状态机路径
-oj 是学习记录结果的json文件路径