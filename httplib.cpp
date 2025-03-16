#pragma once
#include "poll.cpp"
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <format>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <vector>

static constexpr size_t MAX_BUFFER_SIZE = 20 * 1024 * 1024;

static const std::unordered_map<int, std::string> status_codes = {
    {100, "Continue"},
    {101, "Switching Protocols"},
    {102, "Processing"},
    {103, "Early Hints"},
    {200, "OK"},
    {201, "Created"},
    {202, "Accepted"},
    {203, "Non-Authoritative Information"},
    {204, "No Content"},
    {205, "Reset Content"},
    {206, "Partial Content"},
    {207, "Multi-Status"},
    {208, "Already Reported"},
    {226, "IM Used"},
    {300, "Multiple Choices"},
    {301, "Moved Permanently"},
    {302, "Found"},
    {303, "See Other"},
    {304, "Not Modified"},
    {305, "Use Proxy"},
    {307, "Temporary Redirect"},
    {308, "Permanent Redirect"},
    {400, "Bad Request"},
    {401, "Unauthorized"},
    {402, "Payment Required"},
    {403, "Forbidden"},
    {404, "Not Found"},
    {405, "Method Not Allowed"},
    {406, "Not Acceptable"},
    {407, "Proxy Authentication Required"},
    {408, "Request Timeout"},
    {409, "Conflict"},
    {410, "Gone"},
    {411, "Length Required"},
    {412, "Precondition Failed"},
    {413, "Payload Too Large"},
    {414, "URI Too Long"},
    {415, "Unsupported Media Type"},
    {416, "Range Not Satisfiable"},
    {417, "Expectation Failed"},
    {418, "I'm a Teapot"},
    {421, "Misdirected Request"},
    {422, "Unprocessable Entity"},
    {423, "Locked"},
    {424, "Failed Dependency"},
    {425, "Too Early"},
    {426, "Upgrade Required"},
    {428, "Precondition Required"},
    {429, "Too Many Requests"},
    {431, "Request Header Fields Too Large"},
    {451, "Unavailable For Legal Reasons"},
    {500, "Internal Server Error"},
    {501, "Not Implemented"},
    {502, "Bad Gateway"},
    {503, "Service Unavailable"},
    {504, "Gateway Timeout"},
    {505, "HTTP Version Not Supported"},
    {506, "Variant Also Negotiates"},
    {507, "Insufficient Storage"},
    {508, "Loop Detected"},
    {509, "Bandwidth Limit Exceeded"},
    {510, "Not Extended"},
    {511, "Network Authentication Required"}

};
// 去除开头和结尾的空白字符
std::string trim_whitespace(const std::string &str)
{
    const auto first = str.find_first_not_of(" \t\n\r\f\v");
    return (first == std::string::npos) ? "" : str.substr(first, str.find_last_not_of(" \t\n\r\f\v") - first + 1);
}

// 1. +号在路径中保持原样，在query里应解析为空格 (golang)
// 2. %00应认为是风险字符，不允许
static std::optional<std::string> url_decode(const std::string_view &str, const char char_to_space = '+')
{
    std::string out;
    int l = str.length();
    out.reserve(l);
    for (int i = 0; i < l; i++)
    {
        if (str[i] == '%')
        {
            if (i + 2 < l && std::isxdigit(str[i + 1]) && std::isxdigit(str[i + 2]))
            {
                int value;
                auto res = std::from_chars(str.data() + i + 1, str.data() + i + 3, value, 16);
                if (res.ec == std::errc() && value > 0 && value <= 255)
                {
                    out.push_back(value);
                }
                else
                {
                    return std::nullopt; // 非法字符或 %00
                }
                i += 2;
            }
            else
            {
                return std::nullopt;
            }
        }
        else if (str[i] == char_to_space)
        {
            out.push_back(' ');
        }
        else
        {
            out.push_back(str[i]);
        }
    }
    return out;
}

// 解析 HTTP chunked encoding 的 chunk-size
// 格式: chunk-size [;chunk-ext] CRLF
// chunk-size = 1*HEXDIG
// chunk-ext = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
// 参考 RFC 7230 Section 4.1
//
// 返回值: pair<消耗的字符数, chunk size>
// 消耗的字符数:
//   > 0: 成功，返回包含CRLF的总字节数
//   = 0: 需要更多数据
//   < 0: 错误:
//   -1: 无效的输入
//   -2: chunk-size 无效（非法字符或长度不在1-8之间）
//   -3: 无效的行结束符（必须是\r\n）
//   -4: 扩展参数格式错误
std::pair<int, long> parse_chunk_size(const char *buf, int n)
{
    if (!buf || n <= 0)
    {
        return {-1, 0};
    }
    const char *const end = buf + n;
    const char *p = buf;
    // 1. 解析chunk-size (1*HEXDIG)
    const char *hex_start = p;
    while (p < end && std::isxdigit(static_cast<unsigned char>(*p)))
    {
        p++;
    }
    int hex_len = p - hex_start;
    if (hex_len == 0 || hex_len > 8)
    {
        return {-2, 0}; // chunk-size必须是1-8位十六进制数
    }
    // 2. 解析十六进制值
    long chunk_size;
    auto [ptr, ec] = std::from_chars(hex_start, p, chunk_size, 16);
    if (ec != std::errc())
    {
        return {-2, 0};
    }
    // 3. 处理chunk-ext
    if (p < end)
    {
        if (*p == ';')
        {
            p++; // 跳过分号
            // chunk-ext-name = token
            // chunk-ext-val  = token / quoted-string
            while (p < end && *p != '\r')
            {
                char c = *p;
                if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~' || c == '=' || c == ' ' || c == '"'))
                {
                    return {-4, 0};
                }
                p++;
            }
        }
    }
    // 4. 验证CRLF
    // 先检查是否还有足够的数据
    if (p >= end)
    {
        return {0, 0}; // 需要更多数据
    }
    if (*p != '\r')
    {
        return {-3, 0}; // 期望\r但获得其他字符
    }
    if (p + 1 >= end)
    {
        return {0, 0}; // 需要更多数据来验证\n
    }
    if (*(p + 1) != '\n')
    {
        return {-3, 0}; // 期望\n但获得其他字符
    }
    // 成功解析，返回消耗的总字节数（包括CRLF）和chunk大小
    return {static_cast<int>(p - buf + 2), chunk_size};
}

// 仅用于解析HTTP请求行里的URI，不包含?及以后部分，无空格无不可见字符，以/开头，至少输入一个/
// 返回至少一个/，如果返回空意味着解码错误
std::optional<std::string> static decode_path(const std::string &p)
{
    std::vector<std::string> items;
    std::string buf;
    for (char c : p + "/")
    {
        if (c == '/')
        {
            if (!buf.empty())
            {
                if (buf == ".")
                {
                    // skip
                }
                else if (buf == "..")
                {
                    if (!items.empty())
                    {
                        items.pop_back();
                    }
                }
                else
                {
                    auto v = url_decode(buf, ' ');
                    if (!v)
                    {
                        return std::nullopt;
                    }
                    items.emplace_back(std::move(v.value()));
                }
            }
            buf.clear();
        }
        else if (c >= 0x21 && c <= 0x7e)
        {
            buf += c;
        }
        else
        {
            // 字符非法
            return std::nullopt;
        }
    }
    if (items.empty())
    {
        return "/";
    }
    std::ostringstream oss;
    oss << "/";
    std::copy(items.begin(), items.end(), std::ostream_iterator<std::string>(oss, "/")); // 拼接元素后面会跟一个/
    std::string result = oss.str();
    // 如果原始路径不以 '/' 结尾，移除结果中的最后一个 '/'
    if (p.back() != '/')
    {
        result.pop_back();
    }
    return result;
}

std::optional<std::reference_wrapper<const std::string>> map_get_key_value(const std::map<std::string, std::string> &dict, const std::string &key)
{
    auto it = dict.find(key);
    if (it != dict.end())
    {
        return std::cref(it->second);
    }
    return std::nullopt;
}

// value 需要是小写，非空
bool map_key_value_eq(const std::map<std::string, std::string> &dict, const std::string &key, const std::string &value)
{
    auto v = map_get_key_value(dict, key);
    if (!v)
    {
        return false;
    }
    std::string s = v.value();
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s == value;
}

class LimitReader
{
public:
    virtual ~LimitReader() = default;          // 声明为虚函数
    virtual int read(char *buf, int size) = 0; // 纯虚函数接口
    virtual bool eof() const = 0;              // 纯虚函数接口
    virtual void close() = 0;                  // 纯虚函数接口
};

class FileReader : public LimitReader
{
private:
    std::shared_ptr<std::ifstream> file;
    long remaining; // 剩余需要读取的字节数

public:
    FileReader(std::shared_ptr<std::ifstream> f, long length)
        : file(f), remaining(length) {}

    // 读取指定大小的数据，但不超过剩余长度
    int read(char *buf, int size) override
    {
        if (remaining <= 0 || !file || !file->is_open())
        {
            return 0;
        }
        int to_read = std::min(static_cast<long>(size), remaining);
        file->read(buf, to_read);
        int actual_read = file->gcount();
        remaining -= actual_read;
        return actual_read;
    }

    bool eof() const override
    {
        return remaining <= 0 || !file || !file->is_open();
    }

    void close() override
    {
        if (file)
        {
            file->close();
        }
    }
};

class Response
{
    using self = Response;
    using callback = std::function<void(poll_server &, int, int)>;

private:
    enum class State
    {
        READY,        // 初始状态，headers未发送
        HEADERS_SENT, // headers已发送，可以发送body
        FINISHED      // 响应结束(可能是正常完成也可能是出错)
    };

    int fd;
    poll_server &ioServer;

    bool is_once_request = false;
    State state = State::READY;
    int status_code = 200;
    long content_length = -1; // 没有指定content-length，不是第一次就调用end，触发chunked下行编码
    std::shared_ptr<callback> stream_callback = nullptr;

    friend void _reset_response(std::shared_ptr<Response> &obj, bool is_once_request)
    {
        obj->is_once_request = is_once_request;
        obj->state = State::READY;
        obj->status_code = 200;
        obj->content_length = -1;
        obj->stream_callback = nullptr;
    }

    int enqueue(const char *buf, int n, callback callback = nullptr)
    {
        return enqueue(std::string(buf, n), callback);
    }
    // 注意：当非chunked模式下，如果发送0字节，回调是同步执行的，底层忽略发送
    int enqueue(const std::string &s, callback callback = nullptr)
    {
        // chunked编码下允许发送0字节（是作为结束符），否则不允许发送0字节
        if (content_length >= 0)
        {
            if (s.length() < 1)
            {
                if (callback)
                {
                    callback(ioServer, fd, 0);
                }
                return 0;
            }
            return ioServer.write(fd, s, callback);
        }
        std::stringstream ss;
        ss << std::hex << s.length() << "\r\n";
        ss << s << "\r\n";
        return ioServer.write(fd, ss.str(), callback);
    }
    // 下行header key校验
    static bool valid_header_key(const std::string_view &s)
    {
        return std::all_of(s.begin(), s.end(), [](char c)
        { return isalnum(c) || c == '-' || c == '_' || c == '~'; });
    }
    // 下行header value校验
    static bool valid_header_value(const std::string_view &s)
    {
        return std::all_of(s.begin(), s.end(), [](char c)
        { return c >= 0x20 && c <= 0x7e; });
    }
    std::string headers(const std::map<std::string, std::string> &headers)
    {
        const auto t = status_codes.find(status_code);
        const std::string &text = t == status_codes.end() ? "" : t->second;
        std::string result;
        result.reserve(1024);
        result.append("HTTP/1.1 ").append(std::to_string(status_code)).append(" ").append(text).append("\r\nDate: ").append(date()).append("\r\n");
        if (content_length >= 0)
        {
            result.append("Content-Length: ").append(std::to_string(content_length)).append("\r\n");
        }
        else
        {
            result.append("Transfer-Encoding: chunked\r\n");
        }
        for (auto const &[key, val] : headers)
        {
            auto k = trim_whitespace(key);
            std::transform(k.begin(), k.end(), k.begin(), ::tolower);
            if (k != "content-length" && k != "transfer-encoding")
            {
                if (!valid_header_key(k))
                {
                    throw std::runtime_error(std::format("Invalid header key: {}", k));
                }
                if (!valid_header_value(val))
                {
                    throw std::runtime_error(std::format("Invalid header value: {}", val));
                }
                result.append(k).append(": ").append(val).append("\r\n");
            }
        }
        result.append("\r\n");
        return result;
    }

public:
    Response(int f, poll_server &a) : fd(f), ioServer(a)
    {
    }

    // 高效的日期生成函数，返回静态缓冲区的指针
    static const char *date()
    {
        static char buffer[64];
        time_t now = time(0);
        struct tm *tstruct = gmtime(&now);
        strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", tstruct);
        return buffer;
    }

    self *status(int code)
    {
        status_code = code;
        return this;
    }
    self *length(int l)
    {
        content_length = l;
        return this;
    }

    bool writeHead(int code, const std::map<std::string, std::string> &head)
    {
        if (state != State::READY)
        {
            return false;
        }
        status_code = code;
        ioServer.write(fd, headers(head), nullptr);
        state = State::HEADERS_SENT;
        return true;
    }

    int write(const char *str, int n)
    {
        if (n < 1)
        {
            return 0;
        }
        return write(std::string(str, n));
    }

    int write(const std::string &str)
    {
        if (str.length() < 1)
        {
            return 0;
        }
        if (state == State::READY)
        {
            writeHead(status_code, {});
        }
        return enqueue(str);
    };

    int end(const char *str, int n, const std::map<std::string, std::string> &head = {})
    {
        return end(std::string(str, n), head);
    };

    int end(const std::string &s, const std::map<std::string, std::string> &head = {})
    {
        if (state == State::FINISHED)
        {
            return -1;
        }
        if (state == State::READY)
        {
            content_length = s.length();
            writeHead(status_code, head);
        }
        auto cc = [this](poll_server &a, int fd, int out_bytes)
        {
            this->stream_callback = nullptr;
            if (this->is_once_request)
            {
                this->close();
            }
        };
        int ret = 0;
        if (content_length >= 0)
        {
            // 非 chunked 模式，直接用 enqueue 发送
            ret = enqueue(s, cc);
        }
        else
        {
            // chunked 模式
            // 1. 如果有内容，先发送内容（不带回调）
            if (!s.empty())
            {
                ret = enqueue(s, nullptr);
            }
            // 2. 发送结束 chunk（带回调）
            ret = enqueue("", cc);
        }
        state = State::FINISHED;
        return ret;
    }

    // 返回 <0 表示发生错误， 错误码：-1 文件未打开
    // 默认以chunked返回，可以使用length方法提前设置大小，就会非chunked编码
    // 调用此方法不可与write，end等方法混用,也不可调用多次
    int stream(std::shared_ptr<LimitReader> f, const std::map<std::string, std::string> &headers = {})
    {
        if (!f || f->eof() || !(state == State::READY || state == State::HEADERS_SENT))
        {
            return -1;
        }
        if (this->stream_callback) // 防止重复调用
        {
            return -2; // 错误码：流操作已存在
        }
        if (state == State::READY)
        {
            writeHead(status_code, headers);
        }
        char buf[131072];
        int n = f->read(buf, sizeof(buf));
        if (n < 1)
        {
            f->close();
            return end("");
        }
        this->stream_callback = std::make_shared<callback>([this, f](poll_server &a, int fd, int out_bytes)
        {
            if (out_bytes < 1 || this->state != State::HEADERS_SENT)
            {
                // 发送失败
                f->close();
                this->stream_callback.reset(); // 传输完成，释放引用
                return;
            }
            char buf[131072];
            int n = f->read(buf, sizeof(buf));
            if (n > 0)
            {
                this->enqueue(buf, n, *this->stream_callback);
            }
            else
            {
                f->close();
                this->stream_callback.reset(); // 传输完成，释放引用
                this->end("");
            }
        });
        return enqueue(buf, n, *this->stream_callback);
    }

    bool close()
    {
        return ioServer.closefd(fd);
    }
};

class Request
{
private:
    std::shared_ptr<std::stringstream> _body;
    std::map<std::string, std::string> _query;
    std::map<std::string, std::string> _cookies;
    std::function<bool(const char *, int, bool)> _on_body_buf = nullptr;

    // 返回false时中断body接收，断开链接
    friend bool _call_on_body_buf(std::shared_ptr<Request> &obj, const char *buf, int n, bool finish)
    {
        if (obj->_on_body_buf)
        {
            return obj->_on_body_buf(buf, n, finish);
        }
        return true;
    }
    friend void _reset_req(std::shared_ptr<Request> &obj)
    {
        std::stringstream ss;
        obj->_body->swap(ss);
        obj->_query.clear();
        obj->_cookies.clear();
        obj->method.clear();
        obj->uri.clear();
        obj->version.clear();
        obj->path.clear();
        obj->rawQuery.clear();
        obj->headers.clear();
        obj->trailers.clear();
        obj->_on_body_buf = nullptr;
    }

public:
    Request() : _body(std::make_shared<std::stringstream>())
    {
    }
    std::string method;
    std::string uri; // 原始请求uri
    std::string version;

    std::string path;
    std::string rawQuery;

    std::smatch params;

    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> trailers;

    // 注册一个回调函数，每次回调一份body数据，外部可自由处理，返回true则继续接收，false则中断链接；
    // 如果max_body_size>1则内部收集完整body后回调，并要求body数据小于设定值
    void data(std::function<bool(const char *, int, bool)> f, int max_body_size = 0)
    {
        _on_body_buf = max_body_size > 1 ? [body = this->_body, f = std::move(f), maxsize = max_body_size](const char *buf, int n, bool finish)
        {
            if (body->write(buf, n).tellp() > maxsize)
            {
                return false;
            }
            if (finish)
            {
                const std::string &s = body->str();
                bool r = f(s.c_str(), s.size(), true);
                body->clear();
                return r;
            }
            else
            {
                return true;
            }
        } : std::move(f);
    }

    const std::map<std::string, std::string> &query()
    {
        if (this->_query.empty() && !this->rawQuery.empty())
        {
            std::stringstream q(this->rawQuery);
            std::string param;
            while (std::getline(q, param, '&'))
            {
                auto equal_pos = param.find('=');
                if (equal_pos != std::string::npos)
                {
                    auto key = url_decode(param.substr(0, equal_pos));
                    if (key)
                    {
                        auto value = url_decode(param.substr(equal_pos + 1));
                        if (value)
                        {
                            this->_query[key.value()] = value.value();
                        }
                    }
                }
                else
                {
                    auto key = url_decode(param);
                    if (key)
                    {
                        this->_query[key.value()] = "";
                    }
                }
            }
        }
        return this->_query;
    }

    const std::map<std::string, std::string> &cookies()
    {
        if (this->_cookies.empty())
        {
            const auto &x = map_get_key_value(this->headers, "cookie");
            if (x)
            {
                std::stringstream c(x.value());
                std::string cookie;
                while (std::getline(c, cookie, ';'))
                {
                    cookie = trim_whitespace(cookie);
                    auto equal_pos = cookie.find('=');
                    if (equal_pos != std::string::npos)
                    {
                        auto key = url_decode(cookie.substr(0, equal_pos));
                        if (key)
                        {
                            auto value = url_decode(cookie.substr(equal_pos + 1));
                            if (value)
                            {
                                this->_cookies[key.value()] = value.value();
                            }
                        }
                    }
                }
            }
        }
        return this->_cookies;
    }
};

class ConnCtx
{
    using self = ConnCtx;

    enum ParseError
    {
        ERROR_LENGTH_EXCEEDED = -1,
        ERROR_INVALID_CHAR = -2,
        ERROR_VALIDATION_FAILED = -3,
        ERROR_UNKNOW_STATE = -5,
    };

    typedef enum
    {
        STATE_METHOD,        // 开始解析HTTP请求方法，应全部由大写字母组成，1-10个字符，遇到一个空格完成解析
        STATE_REQUEST_LINE,  // 开始解析请求行 需要为ASCII可见字符，1-1000个字符， 遇到一个空格完成解析
        STATE_HTTP_VERSION,  // 开始解析HTTP版本号，需要为ASCII可见字符，1-10个字符，遇到一个换行完成解析
        STATE_HEADERS_KEY,   // 开始解析Header字段名，需要为ASCII可见字符，1-100个字符，遇到一个:号完成解析
        STATE_HEADERS_VALUE, // 开始解析Header字段值，需要为ASCII可见字符，1-900个字符，遇到一个换行完成解析，如果遇到两个换行则跳转到Body解析开始
        STATE_BODY,          // Body数据接收中，Body数据解析完毕后跳转回STATE_METHOD最开始
    } State;

    // HEAD, GET, POST, PUT, PATCH, DELETE, OPTIONS
    static const std::set<char> allowedMethodChars;
    static const std::set<std::string> allowedMethods;
    static const std::set<std::string> bodyMethods;

private:
    State state = STATE_METHOD;
    bool http_10 = false;
    bool http_11 = false;
    std::string buffer;
    std::string h_key; // 临时header key
    bool body_chunked = false;
    long body_length = -1;
    long body_received = 0; // 已经接收的body大小,如果有body_length则为原始接收计数，如果是chunked接收，则累计所有解码的chunked数据
    long current_chunk_size = -1;
    long current_chunk_received = 0;
    std::function<void(self &)> execute;

    void reset()
    {
        _reset_req(this->request);

        this->body_chunked = false;
        this->body_length = -1;
        this->body_received = 0;
        this->current_chunk_size = -1;
        this->current_chunk_received = 0;
        this->h_key.clear();

        state = STATE_METHOD;
    }

    // 当返回>0，表明消耗字节解析完成
    // 当返回=0，表明缺少数据，后续补充数据继续执行
    // 当返回<0，表明协议解析非法，需要上层中断执行
    // 错误码：-1 长度限定不满足，-2字符集不满足，-3校验不满足
    int parse(const char *const buf, int size)
    {
        int eat = 0;
        const char *end = buf + size;
        if (state == STATE_METHOD)
        {
        STATE_METHOD_START:
            const char *start = buf + eat;
            const char *offset = start;
            int method_len = 0;
            while (offset < end)
            {
                char c = *offset++;
                // HEAD, GET, POST, PUT, PATCH, DELETE, OPTIONS
                if (allowedMethodChars.contains(c))
                {
                    method_len++;
                    if (method_len > 10)
                    {
                        return ERROR_LENGTH_EXCEEDED;
                    }
                    continue;
                }
                else if (c == ' ')
                {
                    if (method_len < 1)
                    {
                        return ERROR_INVALID_CHAR;
                    }
                    if (onMethod(start, method_len))
                    {
                        eat += method_len + 1;
                        state = STATE_REQUEST_LINE;
                        goto STATE_REQUEST_LINE_START;
                    }
                    else
                    {
                        return ERROR_VALIDATION_FAILED;
                    }
                }
                else
                {
                    return ERROR_INVALID_CHAR;
                }
            }
            return eat;
        }
        else if (state == STATE_REQUEST_LINE)
        {
        STATE_REQUEST_LINE_START:
            const char *start = buf + eat;
            const char *offset = start;
            int req_len = 0;
            while (offset < end)
            {
                char c = *offset++;
                if (c >= 0x21 && c <= 0x7e)
                {
                    if (req_len == 0 && c != '/') // request uri 必须以/开头
                    {
                        return ERROR_INVALID_CHAR;
                    }
                    req_len++;
                    if (req_len > 1000)
                    {
                        return ERROR_LENGTH_EXCEEDED;
                    }
                    continue;
                }
                else if (c == ' ')
                {
                    if (req_len < 1)
                    {
                        return ERROR_INVALID_CHAR;
                    }
                    if (onRequestURI(start, req_len))
                    {
                        eat += req_len + 1;
                        state = STATE_HTTP_VERSION;
                        goto STATE_HTTP_VERSION_START;
                    }
                    else
                    {
                        return ERROR_VALIDATION_FAILED;
                    }
                }
                else
                {
                    return ERROR_INVALID_CHAR;
                }
            }
            return eat;
        }
        else if (state == STATE_HTTP_VERSION)
        {
        STATE_HTTP_VERSION_START:
            const char *start = buf + eat;
            const char *offset = start;
            int version_len = 0;
            while (offset < end)
            {
                char c = *offset++;
                if (c == 'H' || c == 'T' || c == 'P' || c == '/' || c == '1' || c == '.' || c == '0')
                {
                    version_len++;
                    if (version_len > 10)
                    {
                        return ERROR_LENGTH_EXCEEDED;
                    }
                    continue;
                }
                else if (c == '\r')
                {
                    if (version_len < 1)
                    {
                        return ERROR_INVALID_CHAR;
                    }
                    if (offset < end)
                    {
                        c = *offset++;
                        if (c != '\n')
                        {
                            return ERROR_INVALID_CHAR;
                        }
                        if (onHttpVersion(start, version_len))
                        {
                            eat += version_len + 2;
                            state = STATE_HEADERS_KEY;
                            goto STATE_HEADERS_KEY_START;
                        }
                        else
                        {
                            return ERROR_VALIDATION_FAILED;
                        }
                    }
                    else
                    {
                        return eat;
                    }
                }
                else
                {
                    return ERROR_INVALID_CHAR;
                }
            }
            return eat;
        }
        else if (state == STATE_HEADERS_KEY)
        {
        STATE_HEADERS_KEY_START:
            const char *start = buf + eat;
            const char *offset = start;
            int header_key_len = 0;
            int empty_len = 0;
            while (offset < end)
            {
                char c = *offset++;
                if (isalnum(c) || c == '-' || c == '_' || c == '~')
                {
                    // header key 中间不能包含空格
                    if (empty_len > 0)
                    {
                        return ERROR_INVALID_CHAR;
                    }
                    header_key_len++;
                    if (header_key_len > 100)
                    {
                        return ERROR_LENGTH_EXCEEDED;
                    }
                    continue;
                }
                else if (c == ' ')
                {
                    // header key 开头不能包含空格
                    if (header_key_len < 1)
                    {
                        return ERROR_INVALID_CHAR;
                    }
                    empty_len++;
                }
                else if (c == ':')
                {
                    // 虽然 RFC 7230 规定冒号前面不能有空格，但是我们此处宽松，允许冒号左右有空格
                    if (header_key_len < 1)
                    {
                        return ERROR_INVALID_CHAR;
                    }
                    if (onHeaderKey(start, header_key_len))
                    {
                        eat += header_key_len + empty_len + 1;
                        state = STATE_HEADERS_VALUE;
                        goto STATE_HEADERS_VALUE_START;
                    }
                    else
                    {
                        return ERROR_VALIDATION_FAILED;
                    }
                }
                else
                {
                    return ERROR_INVALID_CHAR;
                }
            }
            return eat;
        }
        else if (state == STATE_HEADERS_VALUE)
        {
        STATE_HEADERS_VALUE_START:
            const char *start = buf + eat;
            const char *offset = start;
            int header_value_len = 0;
            while (offset < end)
            {
                char c = *offset++;
                if (c >= 0x20 && c <= 0x7e)
                {
                    header_value_len++;
                    if (header_value_len > 900)
                    {
                        return ERROR_LENGTH_EXCEEDED;
                    }
                    continue;
                }
                else if (c == '\r')
                {
                    if (header_value_len < 1)
                    {
                        return ERROR_INVALID_CHAR;
                    }
                    if (offset + 2 < end) // 还需探测三个字符 \n\r\n
                    {
                        c = *offset++; // 检查是否有两个换行跳转到body解析
                        char d = *offset++;
                        char e = *offset;
                        if (c != '\n')
                        {
                            return ERROR_INVALID_CHAR;
                        }
                        if (onHeaderValue(start, header_value_len))
                        {
                            if (d == '\r' && e == '\n')
                            {
                                eat += header_value_len + 4;
                                state = STATE_BODY;
                                // 进入body解析流程之前，需要判断body长度和是否chunked
                                const auto &cl = map_get_key_value(this->request->headers, "content-length");
                                if (cl)
                                {
                                    std::stringstream ss(cl.value());
                                    long num;
                                    if (ss >> num && num >= 0)
                                    {
                                        this->body_length = num;
                                    }
                                    else
                                    {
                                        return ERROR_VALIDATION_FAILED; // content-length的值非数字，直接中断
                                    }
                                }
                                this->body_chunked = map_key_value_eq(this->request->headers, "transfer-encoding", "chunked");

                                // 下面解析path和query
                                auto q = this->request->uri.find('?');
                                if (q == std::string::npos)
                                {
                                    auto f = this->request->uri.find('#');
                                    auto path = decode_path(f == std::string::npos ? this->request->uri : this->request->uri.substr(0, f));
                                    if (!path)
                                    {
                                        return ERROR_VALIDATION_FAILED;
                                    }
                                    this->request->path = path.value();
                                }
                                else
                                {
                                    auto path = decode_path(this->request->uri.substr(0, q));
                                    if (!path)
                                    {
                                        return ERROR_VALIDATION_FAILED;
                                    }
                                    this->request->path = path.value();
                                    std::string qq = this->request->uri.substr(q + 1);
                                    auto f = qq.find('#');
                                    this->request->rawQuery = f == std::string::npos ? qq : qq.substr(0, f);
                                }
                                // 此时，路由对应函数调用执行
                                _reset_response(this->response, this->http_10 || map_key_value_eq(this->request->headers, "connection", "close"));
                                execute(*this);
                                goto STATE_BODY_START;
                            }
                            else
                            {
                                eat += header_value_len + 2;
                                state = STATE_HEADERS_KEY;
                                goto STATE_HEADERS_KEY_START;
                            }
                        }
                        else
                        {
                            return ERROR_VALIDATION_FAILED;
                        }
                    }
                    else
                    {
                        return eat;
                    }
                }
                else
                {
                    return ERROR_INVALID_CHAR;
                }
            }
            return eat;
        }
        else if (state == STATE_BODY)
        {
        STATE_BODY_START:
            // 将会多次调用，持续消耗body
            const char *start = buf + eat;
            const int n = end - start;
            // 即使是HEAD GET 等无body请求，也至少会回调一次
            const auto &[used, finish] = onBody(start, n);
            if (used < 0)
            {
                return ERROR_VALIDATION_FAILED;
            }
            eat += used;
            if (finish)
            {
                // 本次请求的body解析完毕, 需要重置一些状态
                this->reset();
                goto STATE_METHOD_START;
            }
            return eat;
        }
        else
        {
            // Unknow State, 不会执行到这里
            return ERROR_UNKNOW_STATE;
        }
    }

    bool onMethod(const char *buf, int n)
    {
        std::string m = std::string(buf, n);
        this->request->method = m;
        return allowedMethods.contains(m);
    }
    bool onRequestURI(const char *buf, int n)
    {
        this->request->uri = std::string(buf, n);
        return true;
    }
    bool onHttpVersion(const char *buf, int n)
    {
        std::string v = std::string(buf, n);
        http_10 = v == "HTTP/1.0";
        http_11 = v == "HTTP/1.1";
        this->request->version = v;
        return http_10 || http_11;
    }
    // 此处存储key状态
    bool onHeaderKey(const char *buf, int n)
    {
        auto s = std::string(buf, n);
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        this->h_key = s;
        return true;
    }
    // 此处检测key已经解析，完成value解析后，key缓存释放
    bool onHeaderValue(const char *buf, int n)
    {
        if (this->h_key.empty())
        {
            return false;
        }
        auto s = trim_whitespace(std::string(buf, n));
        this->request->headers[this->h_key] = s;
        this->h_key.clear();
        return true;
    }
    // 解析一个 header 行，允许前面有空格，忽略前面的空格，虽然 RFC 7230 规定冒号前面不能有空格，但是我们此处宽松，允许冒号左右有空格
    // 返回值: 是否成功解析
    bool parseLineHeader(const char *line, int length, std::string &key, std::string &value)
    {
        if (length <= 0 || line == nullptr)
        {
            return false;
        }
        int keyStart = -1;
        int keyEnd = -1;
        int colonPos = -1;
        bool afterKeySpace = false;
        // 找到 key 的起始位置和冒号位置
        for (int i = 0; i < length; ++i)
        {
            char c = line[i];
            // 找到 key 起始位置
            if (keyStart == -1)
            {
                if (isspace(c))
                {
                    continue; // 跳过 key 前的空格
                }
                // 检查首字符有效性
                if (!isalnum(c) && c != '-' && c != '_' && c != '~')
                {
                    return false;
                }
                keyStart = i;
                keyEnd = i;
            }
            else // 如果已找到 key 起始位置
            {
                // 发现冒号，结束 key 部分
                if (c == ':')
                {
                    colonPos = i;
                    break;
                }
                if (afterKeySpace)
                {
                    // 如果key解析遇到空格，则后续只能是空格直到遇到冒号
                    if (!isspace(c))
                    {
                        return false;
                    }
                }
                else
                {
                    if (isspace(c))
                    {
                        afterKeySpace = true;
                    }
                    else
                    {
                        // 检查字符有效性
                        if (!isalnum(c) && c != '-' && c != '_' && c != '~')
                        {
                            return false;
                        }
                        keyEnd = i;
                    }
                }
            }
        }
        // 验证找到了有效的 key 和冒号
        if (keyStart == -1 || colonPos == -1 || keyEnd < keyStart)
        {
            return false;
        }
        // 处理 value
        int valueStart = -1;
        int valueEnd = -1;
        // 从冒号后开始查找 value
        for (int i = colonPos + 1; i < length; ++i)
        {
            char c = line[i];
            // 找到 value 起始位置
            if (valueStart == -1)
            {
                if (!isspace(c))
                {
                    // 确保 value 只包含可见字符 (ASCII 32-126)
                    if (c < 32 || c > 126)
                    {
                        return false;
                    }
                    valueStart = i;
                    valueEnd = i; // 初始化 valueEnd
                }
            }
            else
            {
                // 确保 value 只包含可见字符 (ASCII 32-126)
                if (c < 32 || c > 126)
                {
                    return false;
                }
                // 更新非空格的 value 结束位置
                if (!isspace(c))
                {
                    valueEnd = i;
                }
            }
        }
        // 提取并转换 key
        key = std::string(line + keyStart, keyEnd - keyStart + 1);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        // value 可以为空
        value = valueStart == -1 ? "" : std::string(line + valueStart, valueEnd - valueStart + 1);
        return true;
    }
    // 处理 HTTP chunked encoding 的数据
    // 返回值: pair<已处理的字节数, 是否完成>
    std::pair<int, bool> handleChunkedBody(const char *buf, int n)
    {
        int used = 0;
        while (used < n)
        {
            if (this->current_chunk_size == -1) // 状态1: 需要解析新的chunk大小
            {
                // 尝试解析chunk size,形如 "1a\r\n"
                auto [chunk_header_size, chunk_size] = parse_chunk_size(buf + used, n - used);
                if (chunk_header_size < 0)
                {
                    return {-1, false};
                }
                if (chunk_header_size == 0) // 数据不足,无法解析完整的chunk size
                {
                    return {used, false};
                }
                used += chunk_header_size;
                this->current_chunk_size = chunk_size;
                this->current_chunk_received = 0;
                if (chunk_size == 0) // chunk_size为0表示收到了最后一个chunk（0\r\n）
                {
                    // 设置一个特殊状态，表示我们正在等待最后的\r\n
                    this->current_chunk_size = -2; // -2 表示等待最后chunk的结束\r\n
                    continue;
                }
                continue; // 继续读取chunk数据
            }
            // 状态2: 正在等待最后chunk后的\r\n或trailer headers
            else if (this->current_chunk_size == -2)
            {
                // 必须保证至少有2个字节才能判断后续是\r\n还是trailer headers
                if (used + 2 > n) // 数据不足，等待更多数据
                {
                    return {used, false};
                }
                // 有足够的字节可以检查是\r\n还是trailer headers
                if (buf[used] == '\r' && buf[used + 1] == '\n')
                {
                    used += 2;
                    bool ok = _call_on_body_buf(this->request, nullptr, 0, true);
                    return {ok ? used : -5, true};
                }
                // 否则 不是\r\n，那就一定是trailer header的开始
                this->current_chunk_size = -3; // 切换到trailer headers解析状态
                continue;
            }
            else if (this->current_chunk_size == -3) // 状态3: 解析trailer headers
            {
                // 寻找完整的trailer header行（以\r\n结尾）
                int line_end = used;
                while (line_end + 1 < n)
                {
                    if (buf[line_end] == '\r' && buf[line_end + 1] == '\n')
                    {
                        break;
                    }
                    line_end++;
                }
                // 如果没找到完整的行，等待更多数据
                if (line_end + 1 >= n || buf[line_end] != '\r' || buf[line_end + 1] != '\n')
                {
                    return {used, false};
                }
                // 解析trailer header行
                int line_length = line_end - used;
                // 检查是否是空行（表示trailer headers结束）
                if (line_length == 0)
                {
                    used += 2; // 跳过\r\n
                    bool ok = _call_on_body_buf(this->request, nullptr, 0, true);
                    return {ok ? used : -6, true};
                }
                // 解析非空的trailer header行
                std::string key, value;
                bool success = parseLineHeader(buf + used, line_length, key, value); // 传入的数据不包含\r\n
                if (success)
                {
                    // 存储trailer header
                    this->request->trailers[key] = value;
                    used = line_end + 2; // 跳过这一行和\r\n
                    continue;            // 继续处理下一行
                }
                else
                {
                    return {-4, false}; // trailer header格式错误
                }
            }
            else
            {
                // 状态4: 读取普通chunk数据
                int chunk_remaining = this->current_chunk_size - this->current_chunk_received;
                int data_available = n - used;
                int read_size = std::min(chunk_remaining, data_available);
                // 读取并处理数据
                if (read_size > 0)
                {
                    if (!_call_on_body_buf(this->request, buf + used, read_size, false))
                    {
                        return {-2, false};
                    }
                    this->body_received += read_size;
                    this->current_chunk_received += read_size;
                    used += read_size;
                }
                // 当前chunk读取完成,检查结尾的\r\n
                if (this->current_chunk_received == this->current_chunk_size)
                {
                    if (used + 2 <= n) // 有足够的字节可以检查\r\n
                    {
                        if (buf[used] != '\r' || buf[used + 1] != '\n')
                        {
                            return {-7, false}; // 格式错误，必须是\r\n
                        }
                        used += 2;
                        this->current_chunk_size = -1; // 重置状态，准备读取下一个chunk
                        continue;
                    }
                    return {used, false}; // 数据不足，等待更多数据
                }
                // chunk数据未读完,等待更多数据
                return {used, false};
            }
        }
        return {used, false};
    }

    // 每次回调部分body数据,当body解析完毕本函数返回true，即使没有body数据，本函数也会回调一次空数据
    // 返回值是本次已解析的字节，通常返回值<=n,当返回-1时，上层需要处理错误终止解析， 如果完成一个解析将返回true
    // 请求方法 POST PUT PATCH 才有body
    std::pair<int, bool> onBody(const char *buf, int n)
    {
        const std::string &m = this->request->method;
        if (!bodyMethods.contains(m))
        {
            return {0, true};
        }
        else if (this->body_chunked)
        {
            return handleChunkedBody(buf, n);
        }
        else if (this->body_length >= 0)
        {
            int remaining = this->body_length - this->body_received;
            int read_size = std::min(remaining, n);
            this->body_received += read_size;
            bool finished = (this->body_received >= this->body_length);
            bool ok = _call_on_body_buf(this->request, buf, read_size, finished);
            return {ok ? read_size : -1, finished};
        }
        // 没有 transfer-encoding:chunked 也没有content-length，但为POST/PUT/PATCH请求，可能HTTP/1.0
        return {n, false};
    }

public:
    std::shared_ptr<Request> request;
    std::shared_ptr<Response> response;
    ConnCtx(int fd, poll_server &a, std::function<void(self &)> f) : execute(f), request(std::make_shared<Request>()), response(std::make_shared<Response>(fd, a)) {};

    // 返回false代表协议解析错误，需要中断链接
    bool recv(const char *b, int n)
    {
        // 拼接之前数据
        buffer.append(b, n);
        int eat = 0;
        int eaten = 0;
        while (buffer.size() > eaten && (eat = parse(buffer.data() + eaten, buffer.size() - eaten)) > 0)
        {
            eaten += eat;
        }
        if (eaten > 0)
        {
            buffer.erase(0, eaten); // 删除已解析的数据
        }
        if (buffer.size() > MAX_BUFFER_SIZE) // 限制解析缓冲区大小，防止内存耗尽
        {
            return false;
        }
        // 如果parse有返回<0,则解析非法
        return eat >= 0;
    }
};

const std::set<char> ConnCtx::allowedMethodChars{'A', 'D', 'E', 'G', 'H', 'L', 'O', 'P', 'S', 'T', 'U'};
const std::set<std::string> ConnCtx::bodyMethods{"POST", "PUT", "PATCH"};
const std::set<std::string> ConnCtx::allowedMethods{"HEAD", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};

using Handler = std::function<void(Request *, Response *)>;

struct route
{
    std::regex pattern;
    Handler fn;
};

class Server
{
    using self = Server;

private:
    const std::string METHOD_HEAD = "HEAD";
    const std::string METHOD_GET = "GET";
    const std::string METHOD_POST = "POST";
    const std::string METHOD_PUT = "PUT";
    const std::string METHOD_PATCH = "PATCH";
    const std::string METHOD_DELETE = "DELETE";
    const std::string METHOD_OPTIONS = "OPTIONS";

    std::unordered_map<std::string, std::vector<route>> routes;

    std::unordered_map<int, std::shared_ptr<ConnCtx>> clients;
    int sockets = 0;

    void defaultHandler(Request *req, Response *res)
    {
        res->status(404)->end("not found");
    }

    void execute(const ConnCtx &c)
    {
        auto r = c.request;
        try
        {
            // 这里for不需要判空，没有异常
            for (const auto &item : routes[r->method])
            {
                if (regex_match(r->path, r->params, item.pattern))
                {
                    item.fn(r.get(), c.response.get());
                    return;
                }
            }
            this->defaultHandler(r.get(), c.response.get());
        }
        catch (...)
        {
            // 处理异常，返回 500 错误
            c.response->status(500)->end("Internal Server Error");
        }
    }

public:
    Server()
    {
    }
    // 返回socket个数，HTTP客户端个数
    std::pair<int, int> status() const
    {
        return {sockets, clients.size()};
    }

    self &head(const std::string &pattern, Handler handler)
    {
        routes[METHOD_HEAD].emplace_back(std::regex(pattern), std::move(handler));
        return *this;
    }

    self &get(const std::string &pattern, Handler handler)
    {
        routes[METHOD_GET].emplace_back(std::regex(pattern), std::move(handler));
        return *this;
    }

    self &post(const std::string &pattern, Handler handler)
    {
        routes[METHOD_POST].emplace_back(std::regex(pattern), std::move(handler));
        return *this;
    }

    self &put(const std::string &pattern, Handler handler)
    {
        routes[METHOD_PUT].emplace_back(std::regex(pattern), std::move(handler));
        return *this;
    }

    self &patch(const std::string &pattern, Handler handler)
    {
        routes[METHOD_PATCH].emplace_back(std::regex(pattern), std::move(handler));
        return *this;
    }

    self &delete_(const std::string &pattern, Handler handler)
    {
        routes[METHOD_DELETE].emplace_back(std::regex(pattern), std::move(handler));
        return *this;
    }

    self &options(const std::string &pattern, Handler handler)
    {
        routes[METHOD_OPTIONS].emplace_back(std::regex(pattern), std::move(handler));
        return *this;
    }

    template <typename Func>
    static auto bind_use_body_handler(Func handler, unsigned int max_size = 65536)
    {
        return [handler, max_size](Request *req, Response *res)
        {
            req->data([req, res, handler](const char *buf, int n, bool finish)
            {
                if (finish)
                {
                    handler(req, res, buf, n);
                }
                return true;
            }, max_size);
        };
    }

    bool start(int port, std::function<int()> timer, std::string host = "")
    {
        auto on_loop = [this, timer](poll_server &a, int n)
        {
            sockets = n;
            return timer();
        };

        auto on_open = [this](poll_server &a, int fd)
        {
            clients[fd] = std::make_shared<ConnCtx>(fd, a, [this](const ConnCtx &c)
            { this->execute(c); });
        };

        // n值为0代表对方关闭了,(recv返回0)
        // -1 代表 收到中断（POLLHUP事件）
        auto on_data = [this](poll_server &a, int fd, const char *buf, int n)
        {
            if (n < 1)
            {
                clients.erase(fd);
                return;
            }
            if (!clients[fd]->recv(buf, n))
            {
                // 如果返回false，代表协议解析不合规，关闭链接
                clients.erase(fd);
                a.closefd(fd);
            }
        };
        poll_server a(on_loop, on_open, on_data);
        return a.start(port, host.c_str());
    }

    ~Server()
    {
    }
};