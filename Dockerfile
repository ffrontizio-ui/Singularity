FROM python:3.11-slim

# Prevent python from writing pyc files to disc and buffering stdout and stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies (lxml needs libxml2 and libxslt)
# We also install build-essential (gcc) for compiling some C extensions
RUN apt-get update && apt-get install -y \
    gcc \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -s /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Ensure appuser owns the /app directory
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port (default FastAPI is 8000)
EXPOSE 8000

# Start command with hot-reload for dev environments
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
