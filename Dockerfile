# Use an official Ubuntu runtime as a parent image
FROM ubuntu:24.04

# Install Python, pip, venv, and sudo
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv sudo

# Create a non-root user and group
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Create restricted_user and set up home directory with rbash as the shell
RUN useradd -m -s /bin/bash restricted_user

# Allow appuser to execute commands as restricted_user without a password
RUN echo "appuser ALL=(restricted_user) NOPASSWD:ALL" >> /etc/sudoers

# Copy the contents of the app directory into the container at /app
COPY app /app

# Copy the restricted_user home directory into the container
COPY restricted_user /home/restricted_user

# Change ownership of the flag.txt file to root and set permissions to read-only for all users
RUN chown root:root /home/restricted_user/flag/flag.txt && chmod 444 /home/restricted_user/flag/flag.txt

# Change ownership and permissions of the flag directory to prevent deletion of its contents
RUN chown root:root /home/restricted_user/flag && chmod 755 /home/restricted_user/flag

# Set the working directory in the container
WORKDIR /app

# Create a virtual environment in /app/venv and install dependencies
RUN python3 -m venv /app/venv && /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Change ownership of the application directory and virtual environment
RUN chown -R appuser:appuser /app

# Ensure the activate script has execute permissions
RUN chmod +x /app/venv/bin/activate

# Switch to the non-root user
USER appuser

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV FLASK_APP=app.py
ENV PATH="/app/venv/bin:$PATH"

# Run the entrypoint script when the container launches
ENTRYPOINT ["/bin/bash", "-c", "source /app/venv/bin/activate && exec python3 app.py"]