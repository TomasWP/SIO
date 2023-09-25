FROM debian:12.1-slim

WORKDIR /app

RUN apt update -y && apt install -y virtualenv
RUN virtualenv venv
ENV PATH=/app/venv/bin:$PATH

COPY requirements.txt ./
RUN pip3 install -r requirements.txt

# ATTENTION: YOU SHOULD NEVER DO THIS! YOUR CONTAINER SHOULD JUST HAVE THE NECESSARY TOOLS TO RUN YOUR APP, AND NOTHING MORE! THIS IS JUST A TESTING ENV
RUN apt install -y iproute2 && apt install -y procps

COPY main.py ./
CMD ["python", "main.py"]
#CMD /bin/bash

