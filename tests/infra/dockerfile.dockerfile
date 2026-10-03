FROM python:3.12-slim
# ruleid: dockerfile-secret-in-env-or-arg
ENV JWT_SECRET=changeme
# ok: dockerfile-secret-in-env-or-arg
ENV PORT=8080
# ruleid: dockerfile-debug-mode
ENV FLASK_DEBUG=1
COPY . /app
# ruleid: dockerfile-world-writable
RUN chmod -R 777 /app
# ruleid: dockerfile-setuid-or-sudo-nopasswd
RUN chmod u+s /usr/bin/find
# ruleid: dockerfile-remote-add
RUN curl -sSL https://example.com/install.sh | sh
CMD ["python", "app.py"]
