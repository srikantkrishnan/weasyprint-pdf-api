FROM python:3.11-slim

# Install system dependencies required by WeasyPrint
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libcairo2 \
    pango1.0-tools \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    libjpeg-dev \
    libxml2 \
    libxslt1.1 \
    fonts-liberation \
    fonts-noto-color-emoji \
    fonts-dejavu \
    curl \
    && apt-get clean

# Set workdir
WORKDIR /app

# Copy requirements and install
COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy your FastAPI app code
COPY ./app /app

# Start the FastAPI app using Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
