#pragma once
#include "httplib.cpp"
#include <unordered_map>

// 全局静态 MIME 类型映射表
static const std::unordered_map<std::string, std::string> mime_types = {
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

    // 默认二进制类型
    {"default", "application/octet-stream"},
};

// 辅助函数：根据文件后缀名获取 MIME 类型
const std::string &get_mime_type(const std::string &path)
{
    // 找到文件后缀
    auto pos = path.find_last_of('.');
    if (pos != std::string::npos)
    {
        std::string ext = path.substr(pos);
        // 大小写无关处理（将扩展名统一转换为小写）
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
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

static std::string path_join(const std::string &dir, const std::string &name)
{
    if (dir.ends_with('/'))
    {
        return dir + name;
    }
    return dir + "/" + name;
}

static std::optional<std::pair<long, long>> parse_range(const std::string &range_str, long file_size)
{
    std::regex range_regex(R"(bytes=(\d*)-(\d*))");
    std::smatch match;
    if (!std::regex_match(range_str, match, range_regex))
    {
        return std::nullopt;
    }
    long start = match[1].str().empty() ? 0 : std::stoul(match[1].str());
    long end = match[2].str().empty() ? file_size - 1 : std::stoul(match[2].str());
    return std::make_pair(start, end);
}

void serve_static(const std::string root, Request *req, Response *res)
{
    const std::string path = root + req->path;
    // 检查文件或目录是否存在
    if (!std::filesystem::exists(path))
    {
        res->status(404)->end("404 Not Found");
        return;
    }
    // 处理文件夹
    if (std::filesystem::is_directory(path))
    {
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
    if (std::filesystem::is_regular_file(path))
    {
        auto file = std::make_shared<std::ifstream>(path, std::ios::binary);
        if (!file->is_open())
        {
            res->status(500)->end("500 Internal Server Error");
            return;
        }
        auto const size = std::filesystem::file_size(path);

        // 获取文件的最后修改时间
        auto file_time = std::filesystem::last_write_time(path);
        auto file_time_t = std::chrono::system_clock::to_time_t(std::chrono::time_point_cast<std::chrono::system_clock::duration>(file_time - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now()));

        // 格式化为 HTTP 日期格式
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&file_time_t), "%a, %d %b %Y %H:%M:%S GMT");
        auto const &last_modified = oss.str();

        // 检查 If-Modified-Since 头
        if (map_key_value_eq(req->headers, "if-modified-since", last_modified))
        {
            // 文件未修改，返回 304 Not Modified
            res->status(304)->end("", {{"Last-Modified", last_modified}});
            return;
        }

        const auto &rr = map_get_key_value(req->headers, "range");
        std::optional<std::pair<int, int>> r;
        if (!rr || !(r = parse_range(rr.value(), size)))
        {
            std::map<std::string, std::string> headers = {
                {"Content-Type", get_mime_type(path)},
                {"Accept-Ranges", "bytes"},
                {"Last-Modified", last_modified}};
            res->length(size)->stream(std::make_shared<FileReader>(file, size), headers);
            return;
        }
        auto const &[start, end] = r.value();
        // 验证范围合法性
        if (start >= size || end >= size || start > end)
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
        res->status(206)->length(length)->stream(std::make_shared<FileReader>(file, length), headers);
        return;
    }
    res->status(404)->end("Not Found");
}
