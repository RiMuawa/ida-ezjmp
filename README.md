# ida-ezjmp

一个简单的 IDA 9.0 插件，通过本地 HTTP 服务接收跳转请求，支持地址跳转和函数名跳转。

## 安装

将 `ida-ezjmp.py` 放入 IDA 插件目录：

```text
IDA/plugins/
```

重新启动 IDA 后，插件会自动在本地启动 HTTP 服务。

## 使用

默认监听地址：

```text
http://127.0.0.1:17321
```

### 按地址跳转

GET 请求：

```text
http://127.0.0.1:17321/jump?ea=0x401000
```

也接受十进制地址：

```text
http://127.0.0.1:17321/jump?ea=4198400
```

POST 请求：

```bash
curl -X POST http://127.0.0.1:17321/jump \
  -H "Content-Type: application/json" \
  -d '{"ea":"0x401000"}'
```

### 按函数名跳转

GET 请求（注意：若通过浏览器访问，部分浏览器可能将 URL 自动转为小写，此时会触发不区分大小写搜索）：

```text
http://127.0.0.1:17321/jump?name=main
```

POST 请求（推荐，保证大小写精确）：

```bash
curl -X POST http://127.0.0.1:17321/jump \
  -H "Content-Type: application/json" \
  -d '{"name":"Main"}'
```

如果未找到精确名称，插件会自动尝试不区分大小写的搜索，并在匹配到唯一函数时跳转。

## 说明

* 仅监听 `127.0.0.1`
* 默认端口 `17321`
* 适用于 IDA 9.0
* 可通过 IDA 插件菜单（`Edit -> Plugins -> Toggle HTTP Jump` 或快捷键 `Ctrl-Alt-J`）启动或停止服务
* 跳转任务由主线程定时处理，保证线程安全


## 致谢🫡🫡🫡

感谢[diredocks](https://github.com/diredocks)为本插件提供的灵感和建议🫡🫡🫡