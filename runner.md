 cd C:\gitlab\
 git config --global --add safe.directory "*"
 .\gitlab-runner.exe run

Вариант 1: network_mode = "host" (для Linux-runner)
Контейнер разделяет сетевой стек хоста — localhost внутри контейнера == localhost хоста. Ничего в коде менять не нужно, LLM_API_BASE_URL=http://localhost:8080 просто работает.

Где настраивается — /etc/gitlab-runner/config.toml на машине раннера:


[[runners]]
  executor = "docker"
  [runners.docker]
    network_mode = "host"
    volumes = [
      "/srv/ai-triage/chroma:/app/rag/chroma_db_metadata",
      "/srv/ai-triage/cache:/app/cache",
      "/srv/ai-triage/output:/app/output",
      "/srv/ai-triage/log:/app/log",
    ]
Volumes нужны чтобы ChromaDB и кэш findings сохранялись между джобами.

Вариант 2: extra_hosts + host.docker.internal (если менять runner не хочется)

[runners.docker]
  extra_hosts = ["host.docker.internal:host-gateway"]
Тогда в CI-переменных: LLM_API_BASE_URL=http://host.docker.internal:8080.

.gitlab-ci.yml

variables:
  IMAGE: registry.example.com/ai-triage:latest

enrich:
  image: $IMAGE
  script:
    - python main.py enrich --test-id $TEST_ID
  when: manual

triage:
  image: $IMAGE
  script:
    - python main.py triage --test-id $TEST_ID --output /app/output/triage_$TEST_ID.jsonl
  artifacts:
    paths:
      - output/
    expire_in: 7 days
  when: manual
Все .env-переменные (DD_API_URL, DD_API_KEY, LLM_API_BASE_URL, LLM_API_MODEL и т.д.) задаются как GitLab CI/CD Variables в настройках проекта (Settings → CI/CD → Variables). Docker runner автоматически пробрасывает их как env-vars в контейнер — load_dotenv() подхватит.