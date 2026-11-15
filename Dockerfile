FROM python:3.12-slim
# Image minimal, tanpa string/pustaka khas honeypot (Bab 8, Jejak sistem).
RUN useradd -m wayang && mkdir -p /data && chown wayang:wayang /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER wayang
VOLUME ["/data"]
CMD ["python", "run_wayang.py"]
