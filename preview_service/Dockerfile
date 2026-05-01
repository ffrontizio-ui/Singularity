FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as a non-root user that comes default with the Playwright image (usually 'pwuser')
# The image mcr.microsoft.com/playwright/python running as pwuser needs perms
RUN chown -R pwuser:pwuser /app
USER pwuser

EXPOSE 8001

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
