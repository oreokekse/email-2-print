FROM python:3.11-slim

# Install system packages: CUPS server + dev headers for pycups build
RUN apt-get update && apt-get install -y \
    cups cups-bsd cups-client \
    libcups2-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# Optional: enable CUPS web UI on 0.0.0.0:631 and allow remote admin
RUN sed -i 's/Listen localhost:631/Port 631/g' /etc/cups/cupsd.conf \
    && sed -i 's/Browsing Off/Browsing On/g' /etc/cups/cupsd.conf \
    && sed -i "s/<Location \/>/<Location \/>\\n  Allow All/g" /etc/cups/cupsd.conf \
    && sed -i "s/<Location \\/admin>/<Location \\/admin>\\n  Allow All/g" /etc/cups/cupsd.conf \
    && sed -i "s/<Location \\/admin\\/conf>/<Location \\/admin\\/conf>\\n  Allow All/g" /etc/cups/cupsd.conf

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/app.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 631

CMD ["/entrypoint.sh"]
