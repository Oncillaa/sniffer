# -*- coding: utf-8 -*-
import socket
import threading
import time
import os
import sys
import json
import re
import base64
from datetime import datetime
from collections import defaultdict

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'

def print_banner():
    print(f"""{Colors.CYAN}
    ╔══════════════════════════════════════════════╗
    ║         NETWORK SNIFFER v2.0                 ║
    ║      HTTP/HTTPS Proxy + Credential Capture   ║
    ╚══════════════════════════════════════════════╝
    {Colors.RESET}""")

class ProxySniffer:
    
    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        self.running = False
        self.lock = threading.Lock()
        
        # Статистика
        self.request_count = 0
        self.credentials_found = []
        self.visited_hosts = set()
        self.requests_log = []
        self.start_time = None
        
    def handle_client(self, client_socket, client_addr):
        try:
            # Читаем запрос от клиента
            request_data = b''
            client_socket.settimeout(10)
            
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk
                    if b'\r\n\r\n' in request_data:
                        break
                except socket.timeout:
                    break
            
            if not request_data:
                client_socket.close()
                return
            
            # Парсим запрос
            request_str = request_data.decode('utf-8', errors='ignore')
            first_line = request_str.split('\r\n')[0] if request_str else ''
            
            # Извлекаем данные
            method = ''
            host = ''
            port = 80
            path = ''
            
            # CONNECT для HTTPS
            connect_match = re.match(r'CONNECT\s+([^:\s]+):(\d+)', first_line)
            if connect_match:
                host = connect_match.group(1)
                port = int(connect_match.group(2))
                method = 'CONNECT'
            else:
                # Обычный HTTP
                match = re.match(r'(\w+)\s+https?://([^/\s]+)(/\S*)?', first_line)
                if match:
                    method = match.group(1)
                    host = match.group(2)
                    path = match.group(3) or '/'
                else:
                    match = re.match(r'(\w+)\s+(/\S*)', first_line)
                    if match:
                        method = match.group(1)
                        path = match.group(2)
                        host_match = re.search(r'Host:\s*([^\r\n]+)', request_str)
                        if host_match:
                            host = host_match.group(1).strip()
            
            if not host:
                client_socket.close()
                return
            
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            with self.lock:
                self.request_count += 1
                self.visited_hosts.add(host)
            
            # Ищем учетные данные
            creds = []
            
            # В URL параметрах
            url_creds = re.findall(
                r'(?:username|user|login|email|pass|password|passwd|pwd|token|secret)=([^&\s]+)',
                request_str, re.IGNORECASE
            )
            if url_creds:
                creds.extend(url_creds)
            
            # В теле POST
            body_match = re.search(r'\r\n\r\n(.+)', request_str, re.DOTALL)
            if body_match:
                body = body_match.group(1)
                body_creds = re.findall(
                    r'(?:username|user|login|email|pass|password|passwd|pwd|secret)=([^&\s]+)',
                    body, re.IGNORECASE
                )
                if body_creds:
                    creds.extend(body_creds)
            
            # Basic Auth
            auth_match = re.search(r'Authorization:\s*Basic\s+(\S+)', request_str)
            if auth_match:
                try:
                    decoded = base64.b64decode(auth_match.group(1)).decode('utf-8', errors='ignore')
                    creds.append(f"BasicAuth:{decoded}")
                except:
                    pass
            
            # Bearer токены
            bearer_match = re.search(r'Authorization:\s*Bearer\s+(\S+)', request_str)
            if bearer_match:
                token = bearer_match.group(1)
                if len(token) > 20:
                    creds.append(f"Bearer:{token[:50]}...")
            
            # Куки с сессиями
            cookie_match = re.search(r'Cookie:\s*([^\r\n]+)', request_str)
            if cookie_match:
                cookie_str = cookie_match.group(1)
                session_cookies = re.findall(r'(?:session|auth|token|sid|jwt)=([^;\s]+)', cookie_str, re.IGNORECASE)
                if session_cookies:
                    creds.append(f"Cookie:{','.join(session_cookies[:2])}")
            
            # Вывод в консоль
            with self.lock:
                if method == 'CONNECT':
                    print(f"\n  {Colors.CYAN}HTTPS{Colors.RESET} {Colors.WHITE}{host}:{port}{Colors.RESET}")
                else:
                    color = Colors.GREEN if method == 'GET' else Colors.YELLOW
                    print(f"\n  {Colors.CYAN}HTTP{Colors.RESET} {color}{method}{Colors.RESET} {Colors.WHITE}{host}{path}{Colors.RESET}")
                
                print(f"    {client_addr[0]} → {host}:{port}")
                
                if creds:
                    print(f"    {Colors.RED}{'═' * 30}{Colors.RESET}")
                    print(f"    {Colors.RED}⚠ ОБНАРУЖЕНЫ ДАННЫЕ:{Colors.RESET}")
                    for c in creds:
                        print(f"    {Colors.RED}{c}{Colors.RESET}")
                    print(f"    {Colors.RED}{'═' * 30}{Colors.RESET}")
                    
                    self.credentials_found.append({
                        'time': timestamp,
                        'host': host,
                        'method': method,
                        'path': path,
                        'credentials': creds,
                        'client': client_addr[0]
                    })
                
                self.requests_log.append({
                    'time': timestamp,
                    'host': host,
                    'method': method,
                    'path': path,
                    'has_creds': len(creds) > 0,
                    'client': client_addr[0]
                })
            
            # Подключаемся к целевому серверу
            try:
                target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target.settimeout(10)
                target.connect((host, port))
                
                if method == 'CONNECT':
                    client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    
                    def forward(src, dst):
                        try:
                            while True:
                                data = src.recv(4096)
                                if not data:
                                    break
                                dst.send(data)
                        except:
                            pass
                    
                    t1 = threading.Thread(target=forward, args=(client_socket, target), daemon=True)
                    t2 = threading.Thread(target=forward, args=(target, client_socket), daemon=True)
                    t1.start()
                    t2.start()
                    t1.join(timeout=30)
                    t2.join(timeout=30)
                else:
                    target.send(request_data)
                    
                    response = b''
                    target.settimeout(3)
                    while True:
                        try:
                            chunk = target.recv(8192)
                            if not chunk:
                                break
                            response += chunk
                            if len(response) > 1048576:  # 1 МБ максимум
                                break
                        except socket.timeout:
                            break
                    
                    if response:
                        client_socket.send(response)
                
                target.close()
                
            except socket.gaierror:
                try:
                    client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\nHost not found')
                except:
                    pass
            except Exception:
                try:
                    client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                except:
                    pass
            
            client_socket.close()
            
        except Exception:
            try:
                client_socket.close()
            except:
                pass
    
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(50)
        server.settimeout(1)
        
        self.running = True
        self.start_time = time.time()
        
        print(f"\n{Colors.BOLD}┌─── HTTP/HTTPS Сниффер ───{Colors.RESET}")
        print(f"│ Адрес : {Colors.GREEN}{self.host}:{self.port}{Colors.RESET}")
        print(f"│")
        print(f"│ {Colors.BOLD}Настройка браузера:{Colors.RESET}")
        print(f"│ Прокси : {Colors.GREEN}{self.host}{Colors.RESET}")
        print(f"│ Порт   : {Colors.GREEN}{self.port}{Colors.RESET}")
        print(f"{'─' * 50}")
        print(f"{Colors.GREEN}[*] Ожидание запросов...{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Открой http://example.com в браузере{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Нажми Ctrl+C для остановки{Colors.RESET}\n")
        
        while self.running:
            try:
                client_socket, client_addr = server.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_addr),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except:
                break
        
        server.close()
    
    def stop(self):
        self.running = False
    
    def show_stats(self):
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n{Colors.BOLD}{'═' * 55}{Colors.RESET}")
        print(f"{Colors.BOLD}  СТАТИСТИКА ПЕРЕХВАТА{Colors.RESET}")
        print(f"{'═' * 55}")
        print(f"  Время работы       : {elapsed:.1f} сек")
        print(f"  Всего запросов     : {self.request_count}")
        print(f"  Уникальных хостов  : {len(self.visited_hosts)}")
        print(f"  Найдено данных     : {Colors.RED}{len(self.credentials_found)}{Colors.RESET}")
        
        if self.visited_hosts:
            print(f"\n{Colors.BOLD}  ПЕРЕХВАЧЕННЫЕ ХОСТЫ:{Colors.RESET}")
            for host in sorted(self.visited_hosts)[:30]:
                print(f"    {Colors.BLUE}{host}{Colors.RESET}")
        
        if self.requests_log:
            print(f"\n{Colors.BOLD}  ВСЕ ЗАПРОСЫ (последние 20):{Colors.RESET}")
            for r in self.requests_log[-20:]:
                marker = f" {Colors.RED}*** ДАННЫЕ ***{Colors.RESET}" if r['has_creds'] else ""
                print(f"    [{r['time']}] {r['method']} {r['host']}{r['path']}{marker}")
        
        if self.credentials_found:
            print(f"\n{Colors.BOLD}  {Colors.RED}ОБНАРУЖЕННЫЕ ДАННЫЕ:{Colors.RESET}")
            for c in self.credentials_found:
                print(f"    [{c['time']}] {c['method']} {c['host']}{c['path']}")
                for cred in c['credentials']:
                    print(f"    {Colors.RED}→ {cred}{Colors.RESET}")
    
    def save_to_file(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"sniffer_report_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("ОТЧЕТ СНИФФЕРА ТРАФИКА\n")
            f.write(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Запросов: {self.request_count}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("ПЕРЕХВАЧЕННЫЕ ХОСТЫ:\n")
            for host in sorted(self.visited_hosts):
                f.write(f"  {host}\n")
            
            f.write("\nВСЕ ЗАПРОСЫ:\n")
            for r in self.requests_log:
                marker = " *** ДАННЫЕ ***" if r['has_creds'] else ""
                f.write(f"  [{r['time']}] {r['method']} {r['host']}{r['path']}{marker}\n")
            
            if self.credentials_found:
                f.write("\n" + "=" * 60 + "\n")
                f.write("ОБНАРУЖЕННЫЕ ДАННЫЕ:\n")
                f.write("=" * 60 + "\n")
                for c in self.credentials_found:
                    f.write(f"\n[{c['time']}] {c['method']} {c['host']}{c['path']}\n")
                    f.write(f"Клиент: {c['client']}\n")
                    for cred in c['credentials']:
                        f.write(f"  {cred}\n")
        
        return filename


def show_menu():
    print(f"\n{Colors.BOLD}Режимы работы:{Colors.RESET}")
    print(f"  {Colors.GREEN}1{Colors.RESET}. Запустить сниффер на порту 8888")
    print(f"  {Colors.GREEN}2{Colors.RESET}. Запустить на своем порту")
    print(f"  {Colors.GREEN}3{Colors.RESET}. Показать инструкцию по настройке")
    print(f"  {Colors.GREEN}0{Colors.RESET}. Выход")


def show_instructions():
    print(f"""
{Colors.BOLD}╔══════════════════════════════════════════════╗
║         КАК НАСТРОИТЬ БРАУЗЕР               ║
╚══════════════════════════════════════════════╝{Colors.RESET}

{Colors.BOLD}Firefox (проще всего):{Colors.RESET}
  1. Открой Настройки
  2. В поиск введи "прокси"
  3. Нажми "Настроить"
  4. Выбери "Ручная настройка прокси"
  5. HTTP прокси: {Colors.GREEN}127.0.0.1{Colors.RESET}, Порт: {Colors.GREEN}8888{Colors.RESET}
  6. Поставь галочку "Также использовать для HTTPS"
  7. Нажми ОК

{Colors.BOLD}Chrome / Яндекс.Браузер:{Colors.RESET}
  1. Установи расширение Proxy SwitchyOmega
  2. Создай новый профиль
  3. Тип: HTTP
  4. Сервер: {Colors.GREEN}127.0.0.1{Colors.RESET}
  5. Порт: {Colors.GREEN}8888{Colors.RESET}
  6. Нажми "Применить"

{Colors.YELLOW}После использования ОБЯЗАТЕЛЬНО отключи прокси!{Colors.RESET}
{Colors.YELLOW}Иначе интернет не будет работать без запущенной программы.{Colors.RESET}
""")


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    print(f"{Colors.BOLD}HTTP/HTTPS Прокси-сниффер{Colors.RESET}")
    print(f"Перехватывает трафик браузера и показывает:\n")
    print(f"  • Посещаемые сайты")
    print(f"  • Логины и пароли (HTTP)")
    print(f"  • Токены авторизации")
    print(f"  • Куки сессий")
    print(f"  • Basic Auth данные")
    print(f"  • Скрытые API запросы\n")
    print(f"{Colors.GREEN}Работает без прав администратора!{Colors.RESET}\n")
    
    while True:
        show_menu()
        choice = input(f"\n  {Colors.CYAN}Ваш выбор →{Colors.RESET} ").strip()
        
        if choice == '0':
            break
        
        if choice == '3':
            show_instructions()
            input(f"\n{Colors.CYAN}Нажмите Enter...{Colors.RESET}")
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            continue
        
        port = 8888
        if choice == '2':
            try:
                port = int(input(f"  Порт: ").strip())
            except:
                print(f"{Colors.RED}Неверный порт{Colors.RESET}")
                continue
        
        if choice not in ['1', '2']:
            continue
        
        sniffer = ProxySniffer(port=port)
        
        try:
            sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
            sniffer_thread.start()
            
            time.sleep(0.5)
            show_instructions()
            
            print(f"{Colors.GREEN}[*] Сниффер запущен и ждет запросы{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Нажмите Ctrl+C для остановки{Colors.RESET}")
            
            while sniffer_thread.is_alive():
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Остановка...{Colors.RESET}")
            sniffer.stop()
            time.sleep(0.5)
        
        sniffer.show_stats()
        
        if sniffer.request_count > 0:
            save = input(f"\n{Colors.CYAN}Сохранить отчет? (y/n): {Colors.RESET}").strip().lower()
            if save in ['y', 'yes', 'д', 'да']:
                fname = sniffer.save_to_file()
                print(f"{Colors.GREEN}[+] Сохранено: {fname}{Colors.RESET}")
        
        input(f"\n{Colors.CYAN}Нажмите Enter...{Colors.RESET}")
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()

if __name__ == '__main__':
    main()