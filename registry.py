#!/usr/bin/python

import requests
from requests.auth import HTTPBasicAuth
import json
import re
import argparse

## this is a registry manipulator, can do following:
##   - list all images (including layers)
##   - delete images
##       - all except last N images
##       - all images and/or tags
##
## run
##   registry.py -h
## to get more help
## or read README.md
##
## important: after removing the tags, run the garbage collector
## on your registry host:
## docker-compose -f [path_to_your_docker_compose_file] run \
##     registry bin/registry garbage-collect \
##     /etc/docker/registry/config.yml
##
## or if you are not using docker-compose:
## docker run registry:2 bin/registry garbage-collect \
##     /etc/docker/registry/config.yml
##
## for more detail on garbage collection read here:
## https://docs.docker.com/registry/garbage-collection/


# number of image versions to keep
CONST_KEEP_LAST_VERSIONS = 10


# class to manipulate registry
class Registry:
    username = ""
    password = ""
    hostname = ""

    # this is required for proper digest processing
    HEADERS = {"Accept":
               "application/vnd.docker.distribution.manifest.v2+json"}

    # store last error if any
    __error = None

    def __init__(self, host, userpass):
        if not ':' in userpass:
            print "Please provide -l in the form USER:PASSWORD"
            exit(1)

        (self.username, self.password) = userpass.split(':')
        self.hostname = host

    def __atoi(self, text):
        return int(text) if text.isdigit() else text

    def __natural_keys(self, text):
        '''
        alist.sort(key=natural_keys) sorts in human order
        http://nedbatchelder.com/blog/200712/human_sorting.html
        (See Toothy's implementation in the comments)
        '''
        return [ self.__atoi(c) for c in re.split('(\d+)', text) ]

    def send(self, path, method="GET"):
        try:
            result = requests.request(
                method, "{}{}".format(self.hostname, path),
                headers = self.HEADERS,
                auth=(self.username, self.password))
        except Exception as error:
            print "cannot connect to {}\nerror {}".format(
                self.hostname,
                error)
            exit(1)
        if str(result.status_code)[0] == '2':
            self.__error = None
            return result

        self.__error=result.status_code
        return None

    def list_images(self):
        result = self.send('/v2/_catalog')
        if result == None:
            return []

        return json.loads(result.text)['repositories']

    def list_tags(self, image_name):
        result = self.send("/v2/{}/tags/list".format(image_name))
        if result == None:
            return []

        tags_list = json.loads(result.text)['tags']

        if tags_list != None:
            tags_list.sort(key=self.__natural_keys)

        return tags_list

    def get_tag_digest(self, image_name, tag):
        image_headers = self.send("/v2/{}/manifests/{}".format(
            image_name, tag), method="HEAD")

        if image_headers == None:

            print "  tag digest not found: {}".format(self.__error)
            return None

        tag_digest = image_headers.headers['Docker-Content-Digest']

        return tag_digest

    def delete_tag(self, image_name, tag, dry_run):
        if dry_run:
            print 'would delete tag {}'.format(tag)
            return True

        tag_digest = self.get_tag_digest(image_name, tag)

        if tag_digest == None:
            return False

        delete_result = self.send("/v2/{}/manifests/{}".format(
            image_name, tag_digest), method="DELETE")

        if delete_result == None:
            print "failed, error: {}".format(self.__error)
            return False

        print "done"
        return True

    def delete_tag_layer(self, image_name, layer_digest, dry_run):
        if dry_run:
            print 'would delete layer {}'.format(layer_digest)
            return False

        print 'deleting layer {}'.format(layer_digest),

        delete_result = self.send('/v2/{}/blobs/{}'.format(
            image_name, layer_digest), method='DELETE')

        if delete_result == None:
            print "failed, error: {}".format(self.__error)
            return False

        print "done"
        return True


    def list_tag_layers(self, image_name, tag):
        layers_result = self.send("/v2/{}/manifests/{}".format(
            image_name, tag))

        if layers_result == None:
            print "error {}".format(self.__error)
            return []

        layers = json.loads(layers_result.text)['layers']

        return layers

def parse_args():
    parser = argparse.ArgumentParser(
        description="List or delete images from Docker registry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("""
IMPORTANT: after removing the tags, run the garbage collector
           on your registry host:

   docker-compose -f [path_to_your_docker_compose_file] run \\
       registry bin/registry garbage-collect \\
       /etc/docker/registry/config.yml

or if you are not using docker-compose:

   docker run registry:2 bin/registry garbage-collect \\
       /etc/docker/registry/config.yml

for more detail on garbage collection read here:
   https://docs.docker.com/registry/garbage-collection/
                """))
    parser.add_argument(
        '-l','--login',
        help="Login and password to access to docker registry",
        required=True,
        metavar="USER:PASSWORD")

    parser.add_argument(
        '-r','--host',
        help="Hostname for registry server, e.g. https://example.com:5000",
        required=True,
        metavar="URL")

    parser.add_argument(
        '-d','--delete',
        help=('If specified, delete all but last {} tags '
              'of all images').format(CONST_KEEP_LAST_VERSIONS),
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '-n','--num',
        help=('Set the number of tags to keep'
              '({} if not set)').format(CONST_KEEP_LAST_VERSIONS),
        default=CONST_KEEP_LAST_VERSIONS,
        nargs='?',
        metavar='N')

    parser.add_argument(
        '--dry-run',
        help=('If used in combination with --delete,'
              'then images will not be deleted'),
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '-i','--image',
        help='Specify images and tags to list/delete',
        nargs='+',
        metavar="IMAGE:[TAG]")

    parser.add_argument(
        '--delete-all',
        help="Will delete all tags. Be careful with this!",
        const=True,
        default=False,
        action="store_const")

    parser.add_argument(
        '--layers',
        help=('Show layers digests for all images and all tags'),
        action='store_const',
        default=False,
        const=True)

    
    return parser.parse_args()


def delete_tags(
    registry, image_name, dry_run, tags_to_delete, keep_last_versions):

    for tag in tags_to_delete:
        print "  deleting tag {}".format(tag)
        for layer in registry.list_tag_layers(image_name, tag):
            layer_digest = layer['digest']
            registry.delete_tag_layer(image_name, layer_digest, dry_run)

        registry.delete_tag(image_name, tag, dry_run)


def main_loop(args):

    keep_last_versions = int(args.num)

    registry = Registry(args.host, args.login)
    if args.delete:
        print "Will delete all but {} last tags".format(keep_last_versions)

    if args.image != None:
        image_list = args.image
    else:
        image_list = registry.list_images()

    # loop through registry's images
    # or through the ones given in command line
    for image_name in image_list:
        print "Image: {}".format(image_name)

        # get tags from arguments if any
        if ":" in image_name:
            (image_name, tag_name) = image_name.split(":")
            tags_list = [tag_name]
        else:
            tags_list = registry.list_tags(image_name)

        if tags_list == None or tags_list == []:
            print "  no tags!"
            continue

        # print tags and optionally layers
        for tag in tags_list:
            print "  tag: {}".format(tag)
            if args.layers:
                for layer in registry.list_tag_layers(image_name, tag):
                    print "    layer: {}, size: {}".format(
                        layer['digest'], layer['size'])

        # delete tags if told so
        if args.delete or args.delete_all:
            if args.delete_all:
                tags_list_to_delete = tags_list
            else:
                tags_list_to_delete = tags_list[:-keep_last_versions]

            delete_tags(
                registry, image_name, args.dry_run,
                tags_list_to_delete, keep_last_versions)

if __name__ == "__main__":
    args = parse_args()
    main_loop(args)
