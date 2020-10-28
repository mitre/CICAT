# Critical Infrastructure Cyberspace Analysis Tool (CICAT) v1.1
#
# Copyright 2020 The MITRE Corporation. All Rights Reserved. 
# Approved for public release. Distribution unlimited. PRS Case #20-2400.
#

from faa-cicat-master directory

  build docker image

    docker build -f docker/Dockerfile -t cicat .

  run docker image (opens an iteractive terminal to work with the cicat tool)

    docker run -it --mount src=$(pwd)/shared,target=/home/cicat/shared,type=bind cicat

      in the terminal:
      
        python cicat/generator/cicat.py >> shared/scengen_out.txt

        exit  (to stop the docker image and return to the host)

    ** --mount, connects a location on the host to set location in the docker image. This allows you to share files between the host and the cicat image. Send your cicat outputs to the target location to easily get your results out of the image.
