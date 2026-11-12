FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    COPILOT_DATA_DIR=/data \
    ASSESSMENT_OLLAMA_URL=http://assessment-ollama:11434 \
    COPILOT_MODEL_DEFAULT=qwen2.5:7b-instruct \
    COPILOT_HOST=0.0.0.0 \
    COPILOT_PORT=8091

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data

EXPOSE 8091

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091"]
