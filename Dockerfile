# Start from a lightweight Python image
FROM python:3.11-slim

# Install Git so our Watchdog can pull updates from GitHub
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Set our working directory inside the container
WORKDIR /app

# Copy and install our requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of our code into the container
COPY . .

# We don't define a CMD here because docker-compose will dictate 
# whether this specific image acts as the Web UI or the Watchdog.