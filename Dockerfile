FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Expose port
EXPOSE 5000

# Run in demo mode
CMD ["python", "backend/server.py", "--demo", "--port", "5000"]