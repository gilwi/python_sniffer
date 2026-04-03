FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy the source code
COPY . .

# Install pytest for testing
RUN pip install pytest

# Ensure the sniffer script is executable
RUN chmod +x sniffer/sniffer.py

# Set the entrypoint to the sniffer script
ENTRYPOINT ["python3", "sniffer/sniffer.py"]
