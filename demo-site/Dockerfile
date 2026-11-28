FROM python:3.12-alpine
WORKDIR /site
RUN adduser -D -H -u 10001 demo && mkdir /state && chown demo:demo /state
COPY server.py ./
COPY dist/ ./dist/
USER demo
EXPOSE 8080
CMD ["python", "-B", "/site/server.py"]
