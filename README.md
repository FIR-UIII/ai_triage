Как заставить работать ollama на cpu
Set parameter 'num_gpu' to '0'
{"model":"llama3:latest","options":{"num_gpu":0}}

Текущее время выполнения примерно 
phi3:mini 10 - 20 cек. 1 запрос
qwen2.5:0.5b 2.4902899265289307 сек

docker pull ollama/ollama:0.15.2

# запустить ollama
docker run -d --cpus=8 -v llm:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
# проверь http://localhost:11434 > Ollama is running
docker exec -it ollama ollama pull nomic-embed-text:v1.5 # или ollama pull nomic-embed-text:v1.5
docker exec -it ollama ollama pull phi3:mini

v2
docker exec -it ollama ollama pull jeffh/intfloat-multilingual-e5-small:q8_0
docker exec -it ollama ollama pull qwen2.5:0.5b

v3 v4
llama-server --hf-repo matrixportal/Phi-4-mini-instruct-Q4_K_M-GGUF --hf-file phi-4-mini-instruct-q4_k_m.gguf -c 204 --offline --metrics
https://llama-cpp-python.readthedocs.io/en/latest/
https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md
