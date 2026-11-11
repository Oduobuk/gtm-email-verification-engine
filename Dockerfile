FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
COPY gtm_verifier/ ./gtm_verifier/

RUN pip install --no-cache-dir dnspython fastapi uvicorn pydantic

EXPOSE 8080

CMD ["uvicorn", "gtm_verifier.api:app", "--host", "0.0.0.0", "--port", "8080"]
