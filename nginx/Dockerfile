# Use an official Nginx runtime as a parent image
FROM nginx:latest

# Remove the default configuration file
RUN rm /etc/nginx/conf.d/default.conf

# Copy the Nginx configuration file into the container
COPY nginx.conf /etc/nginx/nginx.conf

# Copy the .htpasswd file into the container
COPY .htpasswd /etc/nginx/.htpasswd

# Copy the SSL certificates into the container
COPY certs /etc/nginx/certs
