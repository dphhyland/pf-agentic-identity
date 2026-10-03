# Serve the generated microsite with nginx.
# tools/build-microsite.py copies this file into the build directory.
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY site/ /usr/share/nginx/html/

# Railway injects $PORT; nginx:alpine substitutes it into the template at container start.
ENV PORT=8080
EXPOSE 8080
