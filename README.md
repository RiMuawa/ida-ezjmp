# ida-ezjmp

一个简单的 IDA 9.0 插件，用于通过 HTTP 请求控制 IDA 跳转到指定地址。

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

通过浏览器或其他程序访问：

```text
http://127.0.0.1:17321/jump?ea=0x401000
```

也可以使用十进制地址：

```text
http://127.0.0.1:17321/jump?ea=4198400
```

POST 请求示例：

```bash
curl -X POST http://127.0.0.1:17321 \
  -H "Content-Type: application/json" \
  -d '{"ea":"0x401000"}'
```

插件收到请求后，会让 IDA 跳转到对应地址。

## 说明

* 仅监听 `127.0.0.1`
* 默认端口为 `17321`
* 适用于 IDA 9.0
* 可通过 IDA 插件菜单启动或停止服务
