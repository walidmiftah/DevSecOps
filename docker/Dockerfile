FROM python:3.13
WORKDIR /app
COPY ../api .
RUN pip install flask
EXPOSE 5000
CMD [&quot;python&quot;, &quot;app.py&quot;]