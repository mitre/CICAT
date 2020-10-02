#  build docker image
#    docker build -f docker/Dockerfile -t cicat .
#
#  run docker image
#    docker run -it --mount src=$(pwd)/shared,target=/home/cicat/shared,type=bind cicat
#

FROM python:3.6-slim-stretch

RUN useradd -ms /bin/bash cicat
WORKDIR /home/cicat
RUN mkdir shared
RUN apt-get update \
    && apt-get install -y --no-install-recommends 
COPY cicat ./cicat
RUN pwd
RUN ls -Al
RUN pip install --proxy="$http_proxy" -r ./cicat/requirements -I --no-cache-dir 
VOLUME /home/cicat/cicat/
ENTRYPOINT ["/bin/bash"]

