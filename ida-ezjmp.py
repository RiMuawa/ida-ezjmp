# jumper.py - IDA 9.0 兼容修复版（新增按函数名跳转）
import idaapi
import idc
import threading
import json
import socket
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import queue

# 全局变量
http_server = None
server_thread = None
PORT = 17321
jump_queue = queue.Queue()   # 元素格式: ("ea", address) 或 ("name", func_name)
timer_id = None
timer_running = False

class JumpHandler(BaseHTTPRequestHandler):
    """处理HTTP请求的处理器"""
    
    def log_message(self, format, *args):
        # 抑制日志输出
        pass
    
    def do_GET(self):
        """处理GET请求"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            if path == '/jump':
                query_params = parse_qs(parsed_url.query)
                ea_param = query_params.get('ea', [''])[0]
                name_param = query_params.get('name', [''])[0]
                
                # 函数名优先
                if name_param:
                    # 将按名称跳转的任务放入队列（查找将在主线程进行）
                    jump_queue.put(("name", name_param))
                    self._send_success(f'Name jump request queued: {name_param}', name=name_param)
                elif ea_param:
                    try:
                        if ea_param.startswith('0x') or ea_param.startswith('0X'):
                            address = int(ea_param, 16)
                        else:
                            address = int(ea_param)
                        jump_queue.put(("ea", address))
                        self._send_success(f'Address jump request queued for 0x{address:X}', address=hex(address))
                    except ValueError:
                        self._send_error(400, f'Invalid address format: {ea_param}')
                else:
                    self._send_error(400, 'Missing "ea" or "name" parameter')
            else:
                self._send_error(404, f'Path {path} not found')
                
        except Exception as e:
            self._send_error(500, f'Internal error: {str(e)}')
    
    def do_POST(self):
        """处理POST请求"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            name_param = data.get('name', '')
            ea_param = data.get('ea', '')
            
            if name_param:
                jump_queue.put(("name", name_param))
                self._send_success(f'Name jump request queued: {name_param}', name=name_param)
            elif ea_param:
                try:
                    if isinstance(ea_param, str):
                        if ea_param.startswith('0x') or ea_param.startswith('0X'):
                            address = int(ea_param, 16)
                        else:
                            address = int(ea_param)
                    else:
                        address = int(ea_param)
                    jump_queue.put(("ea", address))
                    self._send_success(f'Address jump request queued for 0x{address:X}', address=hex(address))
                except Exception as e:
                    self._send_error(400, f'Invalid address: {str(e)}')
            else:
                self._send_error(400, 'Missing "name" or "ea" field in JSON')
                
        except Exception as e:
            self._send_error(500, f'Internal error: {str(e)}')
    
    def _send_success(self, message, address=None, name=None):
        """发送成功响应"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        resp = {'status': 'success', 'message': message}
        if address:
            resp['address'] = address
        if name:
            resp['name'] = name
        self.wfile.write(json.dumps(resp).encode('utf-8'))
    
    def _send_error(self, code, message):
        """发送错误响应"""
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'status': 'error', 'message': message}).encode('utf-8'))

def process_jump_queue():
    """在主线程中处理跳转队列（此时已在主线程，直接跳转）"""
    try:
        processed = 0
        while not jump_queue.empty():
            task = jump_queue.get_nowait()
            if task[0] == "ea":
                address = task[1]
                print(f"[HTTP Jump] Processing jump to 0x{address:X}")
                try:
                    idc.jumpto(address)
                    print(f"[HTTP Jump] Jumped to 0x{address:X}")
                except Exception as e:
                    print(f"[HTTP Jump] Error jumping to 0x{address:X}: {e}")
            elif task[0] == "name":
                name = task[1]
                print(f"[HTTP Jump] Processing name jump to {name}")
                # 在主线程中查找函数名对应的地址
                addr = idc.get_name_ea_simple(name)
                if addr == idaapi.BADADDR:
                    print(f"[HTTP Jump] Error: function name '{name}' not found")
                else:
                    try:
                        idc.jumpto(addr)
                        print(f"[HTTP Jump] Jumped to {name} at 0x{addr:X}")
                    except Exception as e:
                        print(f"[HTTP Jump] Error jumping to {name} (0x{addr:X}): {e}")
            processed += 1
        
        if processed > 0:
            print(f"[HTTP Jump] Processed {processed} jump(s)")
    except queue.Empty:
        pass
    except Exception as e:
        print(f"[HTTP Jump] Error processing queue: {e}")

def timer_callback():
    """定时器回调 - 返回间隔毫秒数以重复触发，返回0停止"""
    global timer_running
    
    if not timer_running:
        return 0  # 停止定时器
    
    try:
        process_jump_queue()
    except Exception as e:
        print(f"[HTTP Jump] Timer error: {e}")
    
    # 返回100表示100ms后再次调用本函数
    return 100

def start_timer():
    """启动定时器"""
    global timer_running, timer_id
    
    if timer_running:
        return
        
    timer_running = True
    print("[HTTP Jump] Starting timer...")
    
    try:
        # 注册一次性定时器，通过返回值实现周期调用
        timer_id = idaapi.register_timer(100, timer_callback)
        if timer_id is None:
            print("[HTTP Jump] Failed to register timer. Jumps may be delayed.")
        else:
            print(f"[HTTP Jump] Timer registered with ID {timer_id}")
    except Exception as e:
        print(f"[HTTP Jump] Error starting timer: {e}")

def stop_timer():
    """停止定时器"""
    global timer_running, timer_id
    
    timer_running = False
    
    if timer_id is not None:
        try:
            idaapi.unregister_timer(timer_id)
            print("[HTTP Jump] Timer unregistered")
        except Exception as e:
            print(f"[HTTP Jump] Error unregistering timer: {e}")
        timer_id = None

def start_server(port=PORT):
    """启动HTTP服务器"""
    global http_server, server_thread
    
    if http_server:
        print("[HTTP Jump] Server already running")
        return
    
    try:
        http_server = HTTPServer(('127.0.0.1', port), JumpHandler)
        server_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        server_thread.start()
        
        # 启动定时器处理跳转队列
        start_timer()
        
        print(f"[HTTP Jump] HTTP server started on http://127.0.0.1:{port}")
        print(f"[HTTP Jump] Use: http://127.0.0.1:{port}/jump?ea=0xADDRESS  OR  ?name=FuncName")
        
        # 检查端口
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('127.0.0.1', port))
                if result == 0:
                    print(f"[HTTP Jump] Server is listening on port {port}")
                else:
                    print(f"[HTTP Jump] Warning: Port {port} may not be accessible")
        except:
            pass
        
    except OSError as e:
        print(f"[HTTP Jump] Failed to start server: {e}")
        http_server = None
        server_thread = None
    except Exception as e:
        print(f"[HTTP Jump] Unexpected error: {e}")
        http_server = None
        server_thread = None

def stop_server():
    """停止HTTP服务器"""
    global http_server, server_thread
    
    stop_timer()
    
    if http_server:
        print("[HTTP Jump] Stopping HTTP server...")
        try:
            http_server.shutdown()
            http_server.server_close()
        except Exception as e:
            print(f"[HTTP Jump] Error shutting down server: {e}")
        http_server = None
        server_thread = None
        print("[HTTP Jump] Server stopped")

class HTTPJumpPlugin(idaapi.plugin_t):
    """IDA插件主类"""
    
    flags = idaapi.PLUGIN_KEEP
    comment = "HTTP Jump Plugin - Jump to address or function name via HTTP"
    help = "Start HTTP server to receive jump requests (address or function name)"
    wanted_name = "Toggle HTTP Jump"
    
    def init(self):
        print("[HTTP Jump] Plugin initialized for IDA 9.0")
        start_server(PORT)
        print("[HTTP Jump] Press Ctrl-Alt-J to start/stop server")
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        global http_server
        if http_server:
            stop_server()
        else:
            start_server(PORT)
    
    def term(self):
        stop_server()

def PLUGIN_ENTRY():
    return HTTPJumpPlugin()