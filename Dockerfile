# Dockerfile
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Install required dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the port
EXPOSE 8000

# Run the webserver
CMD ["python", "app.py"]