FROM python:3.12-slim-bookworm
WORKDIR /opt/lab
COPY controller.py ./controller.py
COPY static/ ./static/
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin lab
USER 10001:10001
EXPOSE 8844
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "controller"]
