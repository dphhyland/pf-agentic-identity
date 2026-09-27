# The microsite on nginx. `tools/build-microsite.py` assembles the site into build/microsite/
# and copies this file beside it; Railway builds that directory.
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY site/ /usr/share/nginx/html/

# Railway injects $PORT; nginx:alpine substitutes it into the template at container start.
ENV PORT=8080
EXPOSE 8080
