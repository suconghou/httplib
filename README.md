# httplib

基于poll实现的单线程异步HTTP服务器库

基于 https://github.com/suconghou/poll_server 的异步IO

使用状态机解析HTTP协议，支持 HTTP/1.0和HTTP/1.1协议

- 异步非阻塞I/O
- 支持GET、POST、PUT、PATCH、DELETE等HTTP方法
- 支持正则路由匹配
- 支持chunked传输编码
- 内置URL解码和路径解析
- 支持请求头、请求体、响应头的处理
- 支持文件流传输
- 支持keep-alive连接
- 解析query和cookie的辅助方法
- 支持chunked请求的trailer headers

## 快速开始

```cpp
#include "httplib.cpp"

int main() {
    Server server;

    // 注册路由
    server.get("/hello", [](Request* req, Response* res) {
        res->status(200)->end("Hello World");
    });

    // 启动服务器
    server.start(8080, [] { return 3500; });

    return 0;
}
```

## API 介绍

### Server 类
- **get**: 注册GET请求的路由。
  ```cpp
  server.get("/path", [](Request* req, Response* res) {
      // 处理逻辑
  });
  ```
- **post**: 注册POST请求的路由。
  ```cpp
  server.post("/path", [](Request* req, Response* res) {
      // 处理逻辑
  });
  ```
- **put**: 注册PUT请求的路由。
  ```cpp
  server.put("/path", [](Request* req, Response* res) {
      // 处理逻辑
  });
  ```
- **patch**: 注册PATCH请求的路由。
  ```cpp
  server.patch("/path", [](Request* req, Response* res) {
      // 处理逻辑
  });
  ```
- **delete_**: 注册DELETE请求的路由。
  ```cpp
  server.delete_("/path", [](Request* req, Response* res) {
      // 处理逻辑
  });
  ```
- **options**: 注册OPTIONS请求的路由。
  ```cpp
  server.options("/path", [](Request* req, Response* res) {
      // 处理逻辑
  });
  ```
- **start**: 启动服务器，监听指定端口。
  ```cpp
  server.start(8080, [] { return 3500; });
  ```
### 阻止上传

系统默认对未匹配的路由返回404，但不中断TCP连接。
如果是一个POST还可以继续上传数据直到请求体完结，连接复用继续处理下一个请求。

如果要对为未匹配的路由返回404后，立即阻止上传，可以加一个兜底的路由：
```cpp
server.post("/.*", [](Request *req, Response *res)
{
    int limit = 8192;
    req->data([limit](const char *buf, int len, bool finish) mutable -> bool
    {
        limit -= len;
        return limit > 0; // 已发送了404，如果还收到上传的body超过一定量则直接返回false中断连接，不再复用。
    });
    res->status(404)->end("Not Found");
});
```

### 正则路由及捕获参数
- 使用正则表达式注册路由，并捕获路径参数。
  ```cpp
  server.get("/user/(\\d+)", [](Request* req, Response* res) {
      std::string userId = req->params[1]; // 捕获的参数
      res->status(200)->end("User ID: " + userId);
  });
  ```

### bind_use_body_handler 用法示例
- 注册一个处理请求体的回调函数，并与路由注册结合使用。
  ```cpp
  server.post("/submit", Server::bind_use_body_handler([](Request* req, Response* res, const char* data, size_t length) {
      // 处理请求体数据
      std::string body(data, length);
      res->end("Received: " + body);
  }));
  ```

### chunked 传输编码说明
- 在响应头中未指定`Content-Length`时，服务器会自动使用chunked编码。
- 适用于流式传输或动态生成内容的场景。

### Request 类
- **method**: 请求方法（如GET、POST）。
- **uri**: 请求URI。
- **version**: http版本。
- **path**: 请求的path部分。
- **rawQuery**: 请求的query部分。
- **params**: 路由参数
- **headers**: 请求头信息。
- **trailers**: chunked请求的trailer headers
- **query()**: 获取解析后的查询参数。
- **cookies()**: 获取解析后的Cookie。

### Response 类
- **status**: 设置响应状态码。
  ```cpp
  res->status(200);
  ```
- **end**: 结束响应并发送数据。
  ```cpp
  res->end("Response Body");
  ```
- **stream**: 以流的方式发送数据。
  ```cpp
  res->stream(fileReader);
  ```
- **length**: 设置响应的内容长度。
  - 如果设置了`length`，则使用普通编码；如果未设置，则使用chunked编码。
  ```cpp
  res->length(1024);
  ```
- **write**: 写入响应体数据。
  - 在响应头发送后，使用此方法写入数据。
  ```cpp
  res->write("Partial Response");
  ```
- **writeHead**: 发送响应头。
  - 在发送响应体之前调用此方法。
  ```cpp
  res->writeHead(200, {{"Content-Type", "text/plain"}});
  ```

## 构建

编译时需先将 https://github.com/suconghou/poll_server 的`poll.cpp`文件拷贝到当前目录。

`main.cpp` 和 `httplibext.cpp` 为一个示例的HTTP静态文件服务器，支持目录浏览和Range请求。

```bash
g++ -Wall -std=c++20 -O1 main.cpp
```

```bash
g++ -Wall -std=c++20 -flto=auto -static-libstdc++ -static-libgcc --static -Wl,-Bstatic,--gc-sections -O3 -ffunction-sections -fdata-sections main.cpp -o fileserver
```
