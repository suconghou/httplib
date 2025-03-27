#include "httplib.cpp"
#include "httplibext.cpp"
#include <fstream>
#include <getopt.h> // 添加 getopt 头文件
#include <iostream>
#include <sstream>

class MyServer
{
    using self = MyServer;

private:
    std::shared_ptr<Server> s;
    std::string serve_directory = "./"; // 默认服务目录

    void file(Request *req, Response *res) // 普通成员方法
    {
        serve_static(serve_directory, req, res); // 访问非静态成员变量
    }

public:
    MyServer()
    {
        s = std::make_shared<Server>();
        s->get(".*", std::bind(&self::file, this, std::placeholders::_1, std::placeholders::_2)); // 绑定 this
    }
    void run(int argc, char *argv[])
    {
        int port = 8080; // 默认端口
        struct option long_options[] = {
            {"port", required_argument, 0, 'p'},
            {"directory", required_argument, 0, 'd'},
            {0, 0, 0, 0}};

        int c;
        while ((c = getopt_long(argc, argv, "p:d:", long_options, NULL)) != -1)
        {
            switch (c)
            {
            case 'p':
                port = atoi(optarg);
                break;
            case 'd':
                serve_directory = optarg;
                break;
            case '?':
                fprintf(stderr, "未知选项 '-%c'.\n", optopt);
                return;
            default:
                abort();
            }
        }

        s->start(port, []
        { return 3500; });
    }
};

int main(int argc, char *argv[])
{
    try
    {
        MyServer s;
        s.run(argc, argv);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}