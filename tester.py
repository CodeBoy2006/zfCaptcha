import requests
import time
import numpy as np
import sys

# --- 配置 ---
URL = "http://localhost:8080/solve?baseUrl=http://www.gdjw.zjut.edu.cn"
INTERVAL_SECONDS = 3
REQUEST_TIMEOUT = 10  # 请求超时时间（秒）

# --- 数据存储 ---
latencies = []
success_count = 0
total_requests = 0

def print_statistics():
    """计算并打印统计结果"""
    print("\n\n" + "="*20 + " 统计结果 " + "="*20)
    
    if total_requests == 0:
        print("没有发起任何请求。")
        return

    # 计算 'success' 比例
    success_ratio = (success_count / total_requests) * 100 if total_requests > 0 else 0
    
    print(f"总请求次数: {total_requests}")
    print(f"包含 'success' 的响应次数: {success_count}")
    print(f"Success 响应比例: {success_ratio:.2f}%")
    
    # 仅当有成功的延迟记录时才计算延迟统计
    if not latencies:
        print("\n没有记录到任何成功的请求延迟。")
        return
        
    avg_latency = np.mean(latencies)
    p95_latency = np.percentile(latencies, 95)
    p99_latency = np.percentile(latencies, 99)
    
    print("\n--- 延迟统计 (仅限成功建立连接的请求) ---")
    print(f"平均延迟 (avg): {avg_latency:.4f} 秒")
    print(f"P95 延迟: {p95_latency:.4f} 秒")
    print(f"P99 延迟: {p99_latency:.4f} 秒")
    print("="*52)


def main():
    global total_requests, success_count

    print(f"开始请求 URL: {URL}")
    print(f"请求间隔: {INTERVAL_SECONDS} 秒")
    print("按 Ctrl+C 停止并查看统计结果。")
    print("-" * 50)

    try:
        while True:
            total_requests += 1
            try:
                # 发送请求并记录时间
                response = requests.get(URL, timeout=REQUEST_TIMEOUT)
                
                # 记录延迟（秒）
                latency = response.elapsed.total_seconds()
                latencies.append(latency)
                
                # 检查响应内容是否包含 'success'
                if "success" in response.text:
                    success_count += 1
                    status_message = "成功 (含 'success')"
                else:
                    status_message = "成功 (不含 'success')"
                
                print(f"请求 {total_requests}: {status_message} | 状态码: {response.status_code} | 延迟: {latency:.4f}s")

            except requests.exceptions.RequestException as e:
                # 处理网络错误、超时等
                print(f"请求 {total_requests}: 失败 | 错误: {e}")
            
            # 刷新输出缓冲区，确保实时看到日志
            sys.stdout.flush()
            
            # 等待指定间隔
            time.sleep(INTERVAL_SECONDS)

    except KeyboardInterrupt:
        # 用户按下 Ctrl+C
        print_statistics()
    except Exception as e:
        print(f"\n发生未知错误: {e}")
        print_statistics()


if __name__ == "__main__":
    main()