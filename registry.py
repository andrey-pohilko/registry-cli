#!/usr/bin/env python

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
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
##   to get more help
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

# this class is created for testing
class Requests:
    def request(self, method, url, **kwargs):
        return requests.request(method, url, **kwargs)

def natural_keys(text):
    '''
    alist.sort(key=natural_keys) sorts in human order
    http://nedbatchelder.com/blog/200712/human_sorting.html
    (See Toothy's implementation in the comments)
    '''

    def __atoi(text):
        return int(text) if text.isdigit() else text

    return [ __atoi(c) for c in re.split('(\d+)', text) ]


# class to manipulate registry
class Registry:

    # this is required for proper digest processing
    HEADERS = {"Accept":
               "application/vnd.docker.distribution.manifest.v2+json"}

    def __init__(self):
        self.username = None
        self.password = None
        self.hostname = None
        self.no_validate_ssl = False
        self.http = None
        self.last_error = None

    def parse_login(self, login):
        if login != None:

            if not ':' in login:
                self.last_error = "Please provide -l in the form USER:PASSWORD"
                return (None, None)

            self.last_error = None
            (username, password) = login.split(':', 1)
            username = username.strip('"').strip("'")
            password = password.strip('"').strip("'")
            return (username, password)

        return (None, None)


    @staticmethod
    def create(host, login, no_validate_ssl):
        r = Registry()

        (r.username, r.password) = r.parse_login(login)
        if r.last_error != None:
            print(r.last_error)
            exit(1)

        r.hostname = host
        r.no_validate_ssl = no_validate_ssl
        r.http = Requests()
        return r


    def send(self, path, method="GET"):
        # try:
        result = self.http.request(
            method, "{0}{1}".format(self.hostname, path),
            headers = self.HEADERS,
            auth=(None if self.username == ""
                  else (self.username, self.password)),
            verify = not self.no_validate_ssl)

        # except Exception as error:
        #     print("cannot connect to {0}\nerror {1}".format(
        #         self.hostname,
        #         error))
        #     exit(1)
        if str(result.status_code)[0] == '2':
            self.last_error = None
            return result

        self.last_error=result.status_code
        return None

    def list_images(self):
        result = self.send('/v2/_catalog?n=10000')
        if result == None:
            return []

        return json.loads(result.text)['repositories']

    def list_tags(self, image_name):
        result = self.send("/v2/{0}/tags/list".format(image_name))
        if result == None:
            return []

        try:
            tags_list = json.loads(result.text)['tags']
        except ValueError:
            self.last_error = "list_tags: invalid json response"
            return []

        if tags_list != None:
            tags_list.sort(key=natural_keys)

        return tags_list

    # def list_tags_like(self, tag_like, args_tags_like):
    #     for tag_like in args_tags_like:
    #         print("tag like: {0}".format(tag_like))
    #         for tag in all_tags_list:
    #             if re.search(tag_like, tag):
    #                 print("Adding {0} to tags list".format(tag))

    def get_tag_digest(self, image_name, tag):
        image_headers = self.send("/v2/{0}/manifests/{1}".format(
            image_name, tag), method="HEAD")

        if image_headers == None:
            print("  tag digest not found: {0}".format(self.last_error))
            return None

        tag_digest = image_headers.headers['Docker-Content-Digest']

        return tag_digest

    def delete_tag(self, image_name, tag, dry_run, tag_digests_to_ignore):
        if dry_run:
            print('would delete tag {0}'.format(tag))
            return False

        tag_digest = self.get_tag_digest(image_name, tag)

        if tag_digest in tag_digests_to_ignore:
            print("Digest {0} for tag {1} is referenced by another tag or has already been deleted and will be ignored".format(tag_digest, tag))
            return True

        if tag_digest == None:
            return False

        delete_result = self.send("/v2/{0}/manifests/{1}".format(
            image_name, tag_digest), method="DELETE")

        if delete_result == None:
            print("failed, error: {0}".format(self.last_error))
            return False

        tag_digests_to_ignore.append(tag_digest)

        print("done")
        return True

    # this function is not used and thus not tested
    # def delete_tag_layer(self, image_name, layer_digest, dry_run):
    #     if dry_run:
    #         print('would delete layer {0}'.format(layer_digest))
    #         return False
    #
    #     print('deleting layer {0}'.format(layer_digest),)
    #
    #     delete_result = self.send('/v2/{0}/blobs/{1}'.format(
    #         image_name, layer_digest), method='DELETE')
    #
    #     if delete_result == None:
    #         print("failed, error: {0}".format(self.last_error))
    #         return False
    #
    #     print("done")
    #     return True


    def list_tag_layers(self, image_name, tag):
        layers_result = self.send("/v2/{0}/manifests/{1}".format(
            image_name, tag))

        if layers_result == None:
            print("error {0}".format(self.last_error))
            return []

        json_result = json.loads(layers_result.text)
        if json_result['schemaVersion'] == 1:
            layers = json_result['fsLayers']
        else:
            layers = json_result['layers']

        return layers

def parse_args(args = None):
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
        required=False,
        metavar="USER:PASSWORD")

    parser.add_argument(
        '-r','--host',
        help="Hostname for registry server, e.g. https://example.com:5000",
        required=True,
        metavar="URL")

    parser.add_argument(
        '-d','--delete',
        help=('If specified, delete all but last {0} tags '
              'of all images').format(CONST_KEEP_LAST_VERSIONS),
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '-n','--num',
        help=('Set the number of tags to keep'
              '({0} if not set)').format(CONST_KEEP_LAST_VERSIONS),
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
        '--keep-tags',
        nargs='+',
        help="List of tags that will be omitted from deletion if used in combination with --delete or --delete-all",
        required=False,
        default=[])

    parser.add_argument(
        '--tags-like',
        nargs='+',
        help="List of tags (regexp check) that will be handled",
        required=False,
        default=[])

    parser.add_argument(
        '--keep-tags-like',
        nargs='+',
        help="List of tags (regexp check) that will be omitted from deletion if used in combination with --delete or --delete-all",
        required=False,
        default=[])

    parser.add_argument(
        '--no-validate-ssl',
        help="Disable ssl validation",
        action='store_const',
        default=False,
        const=True)

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


    return parser.parse_args(args)


def delete_tags(
    registry, image_name, dry_run, tags_to_delete, tags_to_keep):

    keep_tag_digests = []

    if tags_to_keep:
        print("Getting digests for tags to keep:")
        for tag in tags_to_keep:

            print("Getting digest for tag {0}".format(tag))
            digest = registry.get_tag_digest(image_name, tag)
            if digest is None:
                print("Tag {0} does not exist for image {1}. Ignore here.".format(tag, image_name))
                continue

            print("Keep digest {0} for tag {1}".format(digest, tag))

            keep_tag_digests.append(digest)

    for tag in tags_to_delete:
        if tag in tags_to_keep:
            continue

        print("  deleting tag {0}".format(tag))

##        deleting layers is disabled because
##        it also deletes shared layers
##
##        for layer in registry.list_tag_layers(image_name, tag):
##            layer_digest = layer['digest']
##            registry.delete_tag_layer(image_name, layer_digest, dry_run)

        registry.delete_tag(image_name, tag, dry_run, keep_tag_digests)

def get_tags_like(args_tags_like, tags_list):
    result = set()
    for tag_like in args_tags_like:
        print("tag like: {0}".format(tag_like))
        for tag in tags_list:
            if re.search(tag_like, tag):
                print("Adding {0} to tags list".format(tag))
                result.add(tag)
    return result

def get_tags(all_tags_list, image_name, tags_like):
    # check if there are args for special tags
    result = set()
    if tags_like:
        result = get_tags_like(tags_like, all_tags_list)
    else:
        result.update(all_tags_list)

    # get tags from image name if any
    if ":" in image_name:
        (image_name, tag_name) = image_name.split(":")
        result = set([tag_name])

    return result

def main_loop(args):

    keep_last_versions = int(args.num)

    if args.no_validate_ssl:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    registry = Registry.create(args.host, args.login, args.no_validate_ssl)
    if args.delete:
        print("Will delete all but {0} last tags".format(keep_last_versions))

    if args.image != None:
        image_list = args.image
    else:
        image_list = registry.list_images()

    # loop through registry's images
    # or through the ones given in command line
    for image_name in image_list:
        print("---------------------------------")
        print("Image: {0}".format(image_name))

        all_tags_list = registry.list_tags(image_name)

        if not all_tags_list:
                print("  no tags!")
                continue

        tags_list = get_tags(all_tags_list, image_name, args.tags_like)

        # print(tags and optionally layers
        for tag in tags_list:
            print("  tag: {0}".format(tag))
            if args.layers:
                for layer in registry.list_tag_layers(image_name, tag):
                    if 'size' in layer:
                        print("    layer: {0}, size: {1}".format(
                            layer['digest'], layer['size']))
                    else:
                        print("    layer: {0}".format(
                            layer['blobSum']))

        # add tags to "tags_to_keep" list, if we have regexp "tags_to_keep" entries:
        keep_tags=[]
        if args.keep_tags_like:
            keep_tags.extend(get_tags_like(args.keep_tags_like, tags_list))


        # delete tags if told so
        if args.delete or args.delete_all:
            if args.delete_all:
                tags_list_to_delete = list(tags_list)
            else:
                tags_list_to_delete = sorted(tags_list, key=natural_keys)[:-keep_last_versions]

                # A manifest might be shared between different tags. Explicitly add those
                # tags that we want to preserve to the keep_tags list, to prevent
                # any manifest they are using from being deleted.
                tags_list_to_keep = [tag for tag in tags_list if tag not in tags_list_to_delete]
                keep_tags.extend(tags_list_to_keep)

            delete_tags(
                registry, image_name, args.dry_run,
                tags_list_to_delete, keep_tags)

if __name__ == "__main__":
    args = parse_args()
    try:
        main_loop(args)
    except KeyboardInterrupt:
        print("Ctrl-C pressed, quitting")
        exit(1)

