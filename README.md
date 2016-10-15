# registry-cli
registry.py is a script for easy manipulation of docker-registry from command line (and from scripts)


# Installation

Download registry.py and set it as executable
  chmod 755 registry.py
It uses requests python module, so you may need to install it as well:
  pip install requests


# Listing images

The below command will list all images and all tags in your registry:
  registry.py -l user:pass -r https://example.com:5000

List all images, tags and layers:
  registry.py -l user:pass -r https://example.com:5000 --layers

List particular image(s) or image:tag (all tags of ubuntu and alpine in this example)
  registry.py -l user:pass -r https://example.com:5000 -i ubuntu alpine
  
Same as above but with layers
  registry.py -l user:pass -r https://example.com:5000 -i ubuntu alpine --layers

  
# Deleting images 

Keep only last 10 versions (useful for CI):
Delete all tags of all images but keep last 10 tags (you can put it to your build script
after building images)
  registry.py -l user:pass -r https://example.com:5000 --delete

  If number of tags is less then 10 it will not delete any

You can specify number of tags to keep instead of 10, e.g. 5:
  registry.py -l user:pass -r https://example.com:5000 --delete --num 5

Delete all tags for particular image (e.g. delete all ubuntu tags):
  registry.py -l user:pass -r https://example.com:5000 -i ubuntu --delete-all
  
Delete all tags for all images (do you really want to do it?):
  registry.py -l user:pass -r https://example.com:5000 --delete-all
  
  
# Important notes: 

1. docker registry API does not actually delete tags or images, it marks them for later 
garbage collection. So, make sure you run something like below 
(or put them in your crontab):
   docker-compose -f [path_to_your_docker_compose_file] run \
       registry bin/registry garbage-collect \
       /etc/docker/registry/config.yml

or (if you are not using docker-compose):

   docker run registry:2 bin/registry garbage-collect \
       /etc/docker/registry/config.yml
       
for more detail on garbage collection read here:
   https://docs.docker.com/registry/garbage-collection/

2. Docker registry does not enable image deletion by default. Make sure to enable it by
either creating environment variable 
  REGISTRY_STORAGE_DELETE_ENABLED: "true"
or adding relevant configuration option to the docker-registry's config.yml.
For more on docker-registry configuration, read here:
  https://docs.docker.com/registry/configuration/
  
Please feel free to contact me at anoxis@gmail.com if you wish to add more functionality 
or want to contribute.
  