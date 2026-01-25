FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc-mingw-w64-x86-64 \
    golang \
    rustc \
    cargo \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src ./src
COPY main.py .
# Note: main.py is inside src in the original structure?
# Let's check listing. src/main.py exists.
# We should probably copy everything.
COPY . .

# Create output directory volume
VOLUME /app/output

# Entrypoint
ENTRYPOINT ["python3", "src/main.py"]
