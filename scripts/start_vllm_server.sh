#!/usr/bin/env bash
set -euo pipefail

MODEL_DIR="${MODEL_DIR:-/root/autodl-tmp/co-guard/model/Qwen3-8B}"
SERVED_MODEL_NAME="${SERVED_MODEL_NAME:-Qwen3-8B}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
GPU_MEMORY_UTILIZATION="${GPU_MEMORY_UTILIZATION:-0.9}"
MAX_MODEL_LEN="${MAX_MODEL_LEN:-4096}"

python3 -m vllm.entrypoints.openai.api_server \
  --model "${MODEL_DIR}" \
  --served-model-name "${SERVED_MODEL_NAME}" \
  --host "${HOST}" \
  --port "${PORT}" \
  --dtype auto \
  --gpu-memory-utilization "${GPU_MEMORY_UTILIZATION}" \
  --max-model-len "${MAX_MODEL_LEN}" \
  --trust-remote-code
