import pandas as pd
import time
from tqdm import tqdm

# 从你刚刚编写的模块中引入核心函数
from decompose import run_decomposition, export_to_jsonl

def batch_process_advbench(output_filename="advbench_decomposed.jsonl"):
    """
    自动化读取 AdvBench 数据集并生成拆解数据集。
    """
    # 1. 在线读取 AdvBench 原始 CSV 数据
    csv_url = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv"
    print(f"正在下载并读取 AdvBench 数据集: {csv_url}")
    df = pd.read_csv(csv_url)
    
    # 提取所有恶意目标 (共 520 条)
    malicious_goals = df['goal'].tolist()
    total_goals = len(malicious_goals)
    print(f"成功加载 {total_goals} 条恶意指令，准备利用 M4 本地算力进行拆解...\n")

    # 2. 遍历生成 (加入 tqdm 进度条)
    for index, goal in enumerate(tqdm(malicious_goals, desc="拆解进度")):
        try:
            # 执行拆解逻辑
            # Ollama 会在此处持续调用 Mac 的 MPS 和统一内存
            decomposed_result = run_decomposition(goal)
            
            # 导出到 JSONL
            export_to_jsonl(entry_id=index, original_query=goal, decomposed_result=decomposed_result, filename=output_filename)
            
        except Exception as e:
            # 异常隔离：记录错误并继续执行下一条，防止整个批处理崩溃
            print(f"\n[错误] 第 {index+1} 条指令拆解失败。原指令: {goal}")
            print(f"错误信息: {e}")
            
            # 将失败记录也写入文件，方便后续排查或手动补跑
            export_to_jsonl(original_query=goal, decomposed_result=f"ERROR: {str(e)}", filename="error_log.jsonl")
            
        finally:
            # 给本地模型和内存清理留出极短的缓冲时间，防止因过快并发导致 Ollama 服务无响应
            time.sleep(0.5)

    print(f"\n批处理完成！最终数据集已保存至: {output_filename}")

if __name__ == "__main__":
    # 执行批处理
    batch_process_advbench()