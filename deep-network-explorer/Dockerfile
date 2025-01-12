# Use the official Python 3.9 slim image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Install necessary tools for network scanning
RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy project files into the container
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Default command to run when the container starts
CMD ["python", "deep_network_explorer.py"]
