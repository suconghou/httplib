#pragma once
#include "httplib.cpp"
#include <filesystem>
#include <unordered_map>

// 全局静态 MIME 类型映射表
inline const std::unordered_map<std::string, std::string> mime_types = {
    // 文本类型
    {".html", "text/html"},
    {".htm", "text/html"},
    {".txt", "text/plain"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".csv", "text/csv"},
    {".log", "text/plain"},
    {".sql", "text/plain"},

    // 图片类型
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".bmp", "image/bmp"},
    {".ico", "image/x-icon"},
    {".webp", "image/webp"},
    {".avif", "image/avif"},
    {".svg", "image/svg+xml"},

    // 视频类型
    {".mp4", "video/mp4"},
    {".m4a", "audio/mp4"},
    {".webm", "video/webm"},
    {".mpeg", "video/mpeg"},
    {".mov", "video/quicktime"},
    {".mkv", "video/x-matroska"},
    {".avi", "video/x-msvideo"},
    {".ts", "video/mp2t"},

    // 音频类型
    {".mp3", "audio/mpeg"},
    {".flac", "audio/flac"},
    {".wav", "audio/wav"},
    {".ogg", "audio/ogg"},
    {".aac", "audio/aac"},

    // 文档类型
    {".pdf", "application/pdf"},
    {".doc", "application/msword"},
    {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".xls", "application/vnd.ms-excel"},
    {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},

    // 压缩文件
    {".zip", "application/zip"},
    {".tar", "application/x-tar"},
    {".7z", "application/x-7z-compressed"},
    {".rar", "application/x-rar-compressed"},

    // 字体文件
    {".ttf", "font/ttf"},
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".eot", "application/vnd.ms-fontobject"},

    // 其他类型
    {".xml", "application/xml"},
    {".swf", "application/x-shockwave-flash"},
    {".wasm", "application/wasm"},

    // 默认二进制类型
    {"default", "application/octet-stream"},
};

// 辅助函数：根据文件后缀名获取 MIME 类型
const std::string &get_mime_type(std::string_view path)
{
    // 找到文件后缀
    auto pos = path.find_last_of('.');
    if (pos != std::string::npos)
    {
        std::string ext(path.substr(pos));
        // 大小写无关处理（将扩展名统一转换为小写）
        std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c)
        { return std::tolower(c); });
        // 在 MIME 表中查找
        auto it = mime_types.find(ext);
        if (it != mime_types.end())
        {
            return it->second;
        }
    }
    // 如果未找到匹配，返回默认 MIME 类型
    return mime_types.at("default");
}

std::string time_to_gmt_string(time_t t)
{
    struct tm *tstruct = gmtime(&t);
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", tstruct);
    return std::string(buffer);
}

std::string path_join(const std::string &dir, const std::string &name)
{
    return dir.ends_with('/') ? (dir + name) : (dir + "/" + name);
}

// 解析 "bytes=0-100" 或 "bytes=0-" 或 "bytes=-100"
std::optional<std::pair<int64_t, int64_t>> parse_range(std::string_view s, int64_t size)
{
    if (size <= 0 || !s.starts_with("bytes="))
    {
        return std::nullopt;
    }
    s.remove_prefix(6);
    auto dash = s.find('-');
    if (dash == std::string_view::npos)
    {
        return std::nullopt;
    }
    auto to_int = [](std::string_view sv) -> std::optional<int64_t>
    {
        int64_t v;
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), v);
        return (ec == std::errc{} && ptr == sv.end()) ? std::optional{v} : std::nullopt;
    };
    auto start_opt = to_int(s.substr(0, dash));
    auto end_opt = to_int(s.substr(dash + 1));
    int64_t start = 0, end = size - 1;
    if (start_opt) // 格式: bytes=start-end 或 bytes=start-
    {
        start = *start_opt;
        end = end_opt.value_or(size - 1);
    }
    else if (end_opt) //  格式: bytes=-suffix
    {
        start = std::max<int64_t>(0, size - *end_opt); // 后缀长度超过文件大小则从0开始
    }
    else
    {
        return std::nullopt; // 格式: bytes=- (无效)
    }
    return std::pair{start, std::min(end, size - 1)};
}

std::optional<std::string> resolve_safe_path(const std::filesystem::path &root, const std::filesystem::path &request_path)
{
    try
    {
        auto canonical_root = std::filesystem::canonical(std::filesystem::absolute(root));
        auto full_path = std::filesystem::canonical(canonical_root / request_path.relative_path()).string();
        if (full_path.find(canonical_root.string()) == 0)
        {
            return full_path;
        }
    }
    catch (...)
    {
        // 捕获所有异常
    }
    return std::nullopt;
}

void serve_static(const std::string &root, Request *req, Response *res, bool list_directory = true)
{
    auto safe_path = resolve_safe_path(root, req->path);
    if (!safe_path)
    {
        res->status(404)->end("404 Not Found");
        return;
    }
    auto path = *safe_path;
    // 检查文件或目录是否存在
    struct stat st;
    if (stat(path.c_str(), &st) != 0)
    {
        res->status(404)->end("404 Not Found");
        return;
    }
    // 处理文件夹
    if (S_ISDIR(st.st_mode))
    {
        if (!list_directory)
        {
            res->status(403)->end("403 Forbidden");
            return;
        }
        std::ostringstream oss;
        // 开始生成 HTML 列表
        oss << "<html><head><title>Index of " << req->path << "</title></head><body>";
        oss << "<h1>Index of " << req->path << "</h1><ul>";
        for (const auto &entry : std::filesystem::directory_iterator(path))
        {
            const std::string name = entry.path().filename().string();
            const std::string rel_path = path_join(req->path, name);
            // 显示目录或文件作为链接
            if (entry.is_directory())
            {
                oss << "<li><a href=\"" << rel_path << "/\">" << name << "/</a></li>";
            }
            else
            {
                oss << "<li><a href=\"" << rel_path << "\">" << name << "</a></li>";
            }
        }
        oss << "</ul></body></html>";
        // 返回 HTML 内容
        res->status(200)->end(oss.str(), {{"Content-Type", "text/html; charset=utf-8"}});
        return;
    }
    // 处理文件
    if (!S_ISREG(st.st_mode))
    {
        res->status(403)->end("403 Forbidden");
        return;
    }
    auto file = std::make_unique<std::ifstream>(path, std::ios::binary);
    if (!file->is_open())
    {
        res->status(500)->end("500 Internal Server Error");
        return;
    }
    const int64_t size = st.st_size;

    // 格式化为 HTTP 日期格式
    std::string last_modified = time_to_gmt_string(st.st_mtime);

    // 检查 If-Modified-Since 头
    if (map_key_value_eq(req->headers, "if-modified-since", last_modified))
    {
        // 文件未修改，返回 304 Not Modified
        res->status(304)->end("", {{"Last-Modified", last_modified}});
        return;
    }

    const auto &rr = map_get_key_value(req->headers, "range");
    std::optional<std::pair<int64_t, int64_t>> r;
    if (!rr || !(r = parse_range(rr.value().get(), size)))
    {
        std::map<std::string, std::string> headers = {
            {"Content-Type", get_mime_type(path)},
            {"Accept-Ranges", "bytes"},
            {"Last-Modified", last_modified}};
        res->length(size)->stream(std::make_shared<FileReader>(std::move(file), size), headers);
        return;
    }
    auto const &[start, end] = r.value();
    // 验证范围合法性
    if (start >= size || start > end || end >= size)
    {
        res->status(416)->end("416 Range Not Satisfiable");
        return;
    }
    // 计算需要传输的字节数
    auto const length = end - start + 1;
    // 设置文件读取位置
    file->seekg(start);
    // 设置响应头
    std::map<std::string, std::string> headers = {
        {"Content-Type", get_mime_type(path)},
        {"Content-Range", std::format("bytes {}-{}/{}", start, end, size)},
        {"Accept-Ranges", "bytes"}};
    // 发送 206 Partial Content 响应
    res->status(206)->length(length)->stream(std::make_shared<FileReader>(std::move(file), length), headers);
}
