#!/usr/bin/env python

######
# github repository: https://github.com/andrey-pohilko/registry-cli
# 
# please read more details about the script, usage options and license info there
######

import requests
import ast
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import pprint
import base64
import re
import sys
import os
import argparse
import www_authenticate
from datetime import timedelta, datetime as dt
from getpass import getpass
from multiprocessing.pool import ThreadPool
from dateutil.parser import parse
from dateutil.tz import tzutc

# this is a registry manipulator, can do following:
# - list all images (including layers)
# - delete images
# - all except last N images
# - all images and/or tags
#
# run
# registry.py -h
# to get more help
#
# important: after removing the tags, run the garbage collector
# on your registry host:
# docker-compose -f [path_to_your_docker_compose_file] run \
# registry bin/registry garbage-collect \
# /etc/docker/registry/config.yml
#
# or if you are not using docker-compose:
# docker run registry:2 bin/registry garbage-collect \
# /etc/docker/registry/config.yml
#
# for more detail on garbage collection read here:
# https://docs.docker.com/registry/garbage-collection/


# number of image versions to keep
CONST_KEEP_LAST_VERSIONS = 10

# print debug messages
DEBUG = False

MAX_THREADS = 30


def limit_threads(target_list):
    count = len(target_list)
    if count <= MAX_THREADS:
        return count
    else:
        return MAX_THREADS


# this class is created for testing
class Requests:

    def request(self, method, url, **kwargs):
        return requests.request(method, url, **kwargs)

    def bearer_request(self, method, url, auth, **kwargs):
        global DEBUG
        if DEBUG: print("[debug][funcname]: bearer_request()")

        if DEBUG:
            print('[debug][registry][request]: {0} {1}'.format(method, url))
            if 'Authorization' in kwargs['headers']:
                print('[debug][registry][request]: Authorization header:')

                token_parsed = kwargs['headers']['Authorization'].split('.')
                pprint.pprint(ast.literal_eval(decode_base64(token_parsed[0])))
                pprint.pprint(ast.literal_eval(decode_base64(token_parsed[1])))

        res = requests.request(method, url, **kwargs)
        if str(res.status_code)[0] == '2':
            if DEBUG: print("[debug][registry] accepted")
            return (res, kwargs['headers']['Authorization'])

        if res.status_code == 401:
            if DEBUG: print("[debug][registry] Access denied. Refreshing token...")
            oauth = www_authenticate.parse(res.headers['Www-Authenticate'])

            if DEBUG:
                print('[debug][auth][answer] Auth header:')
                pprint.pprint(oauth['bearer'])

            # print('[info] retreiving bearer token for {0}'.format(oauth['bearer']['scope']))
            request_url = '{0}'.format(oauth['bearer']['realm'])
            query_separator = '?'
            if 'service' in oauth['bearer']:
                request_url += '{0}service={1}'.format(query_separator, oauth['bearer']['service'])
                query_separator = '&'
            if 'scope' in oauth['bearer']:
                request_url += '{0}scope={1}'.format(query_separator, oauth['bearer']['scope'])

            if DEBUG:
                print('[debug][auth][request] Refreshing auth token: POST {0}'.format(request_url))

            if args.auth_method == 'GET':
                try_oauth = requests.get(request_url, auth=auth, **kwargs)
            else:
                try_oauth = requests.post(request_url, auth=auth, **kwargs)

            try:
                oauth_response = ast.literal_eval(try_oauth._content.decode('utf-8'))
                token = oauth_response['access_token'] if 'access_token' in oauth_response else oauth_response['token']
            except SyntaxError:
                print('\n\n[ERROR] couldnt accure token: {0}'.format(try_oauth._content))
                sys.exit(1)

            if DEBUG:
                print('[debug][auth] token issued: ')
                token_parsed=token.split('.')
                pprint.pprint(ast.literal_eval(decode_base64(token_parsed[0])))
                pprint.pprint(ast.literal_eval(decode_base64(token_parsed[1])))

            kwargs['headers']['Authorization'] = 'Bearer {0}'.format(token)
        else:
            return (res, kwargs['headers']['Authorization'])

        res = requests.request(method, url, **kwargs)
        return (res, kwargs['headers']['Authorization'])


def natural_keys(text):
    """
    alist.sort(key=natural_keys) sorts in human order
    http://nedbatchelder.com/blog/200712/human_sorting.html
    (See Toothy's implementation in the comments)
    """

    def __atoi(text):
        return int(text) if text.isdigit() else text

    return [__atoi(c) for c in re.split('(\d+)', text)]


def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    data = data.replace('Bearer ','')
    # print('[debug] base64 string to decode:\n{0}'.format(data))
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)
    return base64.decodestring(data)


def get_error_explanation(context, error_code):
    error_list = {"delete_tag_405": 'You might want to set REGISTRY_STORAGE_DELETE_ENABLED: "true" in your registry',
                  "get_tag_digest_404": "Try adding flag --digest-method=GET"}

    key = "%s_%s" % (context, error_code)

    if key in error_list.keys():
        return(error_list[key])

    return ''


def get_auth_schemes(r,path):
    """ Returns list of auth schemes(lowcased) if www-authenticate: header exists
         returns None if no header found
         - www-authenticate: basic
         - www-authenticate: bearer
    """

    if DEBUG: print("[debug][funcname]: get_auth_schemes()")

    try_oauth = requests.head('{0}{1}'.format(r.hostname,path), verify=not r.no_validate_ssl)

    if 'Www-Authenticate' in try_oauth.headers:
        oauth = www_authenticate.parse(try_oauth.headers['Www-Authenticate'])
        if DEBUG:
            print('[debug][docker] Auth schemes found:{0}'.format([m for m in oauth]))
        return [m.lower() for m in oauth]
    else:
        if DEBUG:
            print('[debug][docker] No Auth schemes found')
        return []


# class to manipulate registry
class Registry:
    # this is required for proper digest processing
    HEADERS = {"Accept":
               "application/vnd.docker.distribution.manifest.v2+json"}

    def __init__(self):
        self.username = None
        self.password = None
        self.auth_schemes = []
        self.hostname = None
        self.no_validate_ssl = False
        self.http = None
        self.last_error = None
        self.digest_method = "HEAD"

    def parse_login(self, login):
        if login is not None:

            if ':' not in login:
                self.last_error = "Please provide -l in the form USER:PASSWORD"
                return (None, None)

            self.last_error = None
            (username, password) = login.split(':', 1)
            username = username.strip('"').strip("'")
            password = password.strip('"').strip("'")
            return (username, password)

        return (None, None)


    @staticmethod
    def _create(host, login, no_validate_ssl, digest_method = "HEAD"):
        r = Registry()

        (r.username, r.password) = r.parse_login(login)
        if r.last_error is not None:
            print(r.last_error)
            sys.exit(1)

        r.hostname = host
        r.no_validate_ssl = no_validate_ssl
        r.http = Requests()
        r.digest_method = digest_method
        return r

    @staticmethod
    def create(*args, **kw):
        return Registry._create(*args, **kw)

    def send(self, path, method="GET"):
        if 'bearer' in self.auth_schemes:
            (result, self.HEADERS['Authorization']) = self.http.bearer_request(
                method, "{0}{1}".format(self.hostname, path),
                auth=(('', '') if self.username in ["", None]
                    else (self.username, self.password)),
                headers=self.HEADERS,
                verify=not self.no_validate_ssl)
        else:
            result = self.http.request(
                method, "{0}{1}".format(self.hostname, path),
                headers=self.HEADERS,
                auth=(None if self.username == "" else (self.username, self.password)),
                verify=not self.no_validate_ssl)

        if str(result.status_code)[0] == '2':
            self.last_error = None
            return result

        self.last_error = result.status_code
        return None

    def list_images(self):
        result = self.send('/v2/_catalog?n=10000')
        if result is None:
            return []

        return json.loads(result.text)['repositories']

    def list_tags(self, image_name):
        result = self.send("/v2/{0}/tags/list".format(image_name))
        if result is None:
            return []

        try:
            tags_list = json.loads(result.text)['tags']
        except ValueError:
            self.last_error = "list_tags: invalid json response"
            return []

        if tags_list is not None:
            tags_list.sort(key=natural_keys)

        return tags_list

    def get_tag_digest(self, image_name, tag):
        image_headers = self.send("/v2/{0}/manifests/{1}".format(
            image_name, tag), method=self.digest_method)

        if image_headers is None:
            print("  tag digest not found: {0}.".format(self.last_error))
            print(get_error_explanation("get_tag_digest", self.last_error))
            return None

        tag_digest = image_headers.headers['Docker-Content-Digest']

        return tag_digest

    def get_keep_digests(self, image_name, tags_to_keep):
        if not tags_to_keep:
            return []
        digests_to_keep = []
        pool = ThreadPool(limit_threads(tags_to_keep))
        results = {}
        success = []
        failed = []

        for tag in tags_to_keep:
            print("Getting digest for tag {0}".format(tag))
            results[tag] = pool.apply_async(self.get_tag_digest, args=(image_name, tag))
        for tag in results.keys():
            result = results.get(tag)
            digest = result.get()
            if digest is None:
                failed.append("Digest does not exist for tag {0} in image {1}. Ignore here.".format(tag, image_name, ))
            else:
                success.append("Digest {0} referred by tag {1}".format(digest, tag))
                if digest not in digests_to_keep:
                    digests_to_keep.append(digest)

        if success:
            print('\n\nFound digest to preserve:')
            print('---------------------------------')
            for digest in digests_to_keep:
                print(digest)
            print('\nDigest references:')
            for message in success:
                print(message)

        if failed:
            print('\nWhile running search following errors occurred:')
            for message in failed:
                print(message)
            print('---------------------------------')

        pool.close()
        pool.join()

        return digests_to_keep

    def get_delete_digests(self, image_name, tags_to_delete, digests_to_keep):
        if not tags_to_delete:
            return []
        digests_to_delte = []
        pool = ThreadPool(limit_threads(tags_to_delete))
        results = {}
        success = []
        failed = []
        ignored_digests = []
        ignored = []

        for tag in tags_to_delete:
            print("Getting digest for tag {0}".format(tag))
            results[tag] = pool.apply_async(self.get_tag_digest, args=(image_name, tag))
        for tag in results.keys():
            result = results.get(tag)
            digest = result.get()
            if digest is None:
                failed.append("Digest does not exist for tag {0} in image {1}. Ignore here.".format(tag, image_name, ))
            elif digest in digests_to_keep:
                ignored_digests.append(digest)
                ignored.append("Digest {0} for tag {1} is referenced by another tag that should be kept.".format(digest, tag))
            else:
                success.append("Digest {0} for tag {1} can be deleted.".format(digest, tag))
                if digest not in digests_to_delte:
                    digests_to_delte.append(digest)

        if ignored:
            print("\n\nFollowing digests can not be deleted:")
            print('---------------------------------')
            for digest in ignored_digests:
                print(digest)
            print("\nReasons:")
            for message in ignored:
                print(message)
        if success:
            print("\n\nFollowing digests shall be deleted:")
            print('---------------------------------')
            for digest in digests_to_delte:
                print(digest)
            print("\nEvaluation:")
            for message in success:
                print(message)
        if failed:
            print("\nWhile running search following errors occurred:")
            print('---------------------------------')
            for message in failed:
                print(message)

        pool.close()
        pool.join()

        return digests_to_delte

    def delete_digest(self, image_name, digest, dry_run):
        if dry_run:
            status = True
            reason = "Would delete digest {0}".format(digest)
        else:
            print("Deleting digest: \"{0}\"".format(digest))
            delete_digest = self.send("/v2/{0}/manifests/{1}".format(image_name, digest),
                                      method="DELETE")

            if delete_digest is None:
                reason = "failed, error: {0}".format(self.last_error)
                reason = reason + "\n  " + get_error_explanation("delete_tag", self.last_error)
                status = False
            else:
                status = True
                reason = "Deleted digest {0}".format(digest)

        return status, reason

    # # This function is not used anymore!
    # def delete_digest_for_tag(self, image_name, tag, dry_run, tag_digests_to_ignore):
    #     tag_digest = self.get_tag_digest(image_name, tag)
    #
    #     if tag_digest in tag_digests_to_ignore:
    #         reason = "Digest {0} for tag {1} is referenced by another tag or has already been deleted and will be ignored".format(
    #             tag_digest, tag)
    #         status = False
    #
    #     elif tag_digest is None:
    #         status = False
    #         reason = "Digest not found for tag {0} ".format(tag)
    #
    #     elif dry_run:
    #         status = True
    #         reason = "Would delete tag {0}".format(tag)
    #
    #     else:
    #         print("Deleting tag: \"{0}\".format(tag)")
    #         delete_result = self.send("/v2/{0}/manifests/{1}".format(image_name, tag_digest),
    #                                   method="DELETE")
    #
    #         if delete_result is None:
    #             reason = "failed, error: {0}".format(self.last_error)
    #             reason = reason + "\n  " + get_error_explanation("delete_tag", self.last_error)
    #             status = False
    #         else:
    #             status = True
    #             reason = "Deleted tag {0}".format(tag)
    #
    #     tag_digests_to_ignore.append(tag_digest)
    #
    #     return status, reason

    def list_tag_layers(self, image_name, tag):
        layers_result = self.send("/v2/{0}/manifests/{1}".format(
            image_name, tag))

        if layers_result is None:
            print("error {0}".format(self.last_error))
            return []

        json_result = json.loads(layers_result.text)
        if json_result['schemaVersion'] == 1:
            layers = json_result['fsLayers']
        else:
            layers = json_result['layers']

        return layers

    def get_tag_config(self, image_name, tag):
        config_result = self.send(
            "/v2/{0}/manifests/{1}".format(image_name, tag))

        if config_result is None:
            print("  tag digest not found: {0}".format(self.last_error))
            return []

        json_result = json.loads(config_result.text)
        if json_result['schemaVersion'] == 1:
            print("Docker schemaVersion 1 isn't supported for deleting by age.")
            sys.exit(1)
        else:
            tag_config = json_result['config']

        return tag_config

    def get_image_age(self, image_name, image_config):
        container_header = {"Accept": "{0}".format(
            image_config['mediaType'])}

        if 'bearer' in self.auth_schemes:
            container_header['Authorization'] = self.HEADERS['Authorization']
            (response, self.HEADERS['Authorization']) = self.http.bearer_request("GET", "{0}{1}".format(self.hostname, "/v2/{0}/blobs/{1}".format(
                image_name, image_config['digest'])),
                auth=(('', '') if self.username in ["", None]
                    else (self.username, self.password)),
                headers=container_header,
                verify=not self.no_validate_ssl)
        else:
            response = self.http.request("GET", "{0}{1}".format(self.hostname, "/v2/{0}/blobs/{1}".format(
                image_name, image_config['digest'])),
                headers=container_header,
                auth=(None if self.username == ""
                    else (self.username, self.password)),
                verify=not self.no_validate_ssl)

        if str(response.status_code)[0] == '2':
            self.last_error = None
            image_age = json.loads(response.text)
            return image_age['created']
        else:
            print(" blob not found: {0}".format(self.last_error))
            self.last_error = response.status_code
            return []


def parse_args(args=None):
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
        '-l', '--login',
        help="Login and password for access to docker registry",
        required=False,
        metavar="USER:PASSWORD")
    
    parser.add_argument(
        '-w', '--read-password',
        help="Read password from stdin (and prompt if stdin is a TTY); " +
             "the final line-ending character(s) will be removed; " +
             "the :PASSWORD portion of the -l option is not required and " +
             "will be ignored",
        action='store_const',
        default=False,
        const=True)
    
    parser.add_argument(
        '-r', '--host',
        help="Hostname for registry server, e.g. https://example.com:5000",
        required=True,
        metavar="URL")
    
    parser.add_argument(
        '-d', '--delete',
        help=('If specified, delete all but last {0} tags').format(CONST_KEEP_LAST_VERSIONS),
        action='store_const',
        default=False,
        const=True)
    
    parser.add_argument(
        '-n', '--num',
        help=('Set the number of tags to keep'
              '(Default: {0})').format(CONST_KEEP_LAST_VERSIONS),
        default=None,
        nargs='?',
        metavar='N')
    
    parser.add_argument(
        '--debug',
        help=('Turn debug output'),
        action='store_const',
        default=False,
        const=True)
    
    parser.add_argument(
        '--dry-run',
        help=('If used in combination with --delete,'
              'then images will not be deleted'),
        action='store_const',
        default=False,
        const=True)
    
    parser.add_argument(
        '-i', '--image',
        help='Specify images and tags to list/delete',
        nargs='+',
        metavar="IMAGE:[TAG]")
    
    parser.add_argument(
        '--images-like',
        nargs='+',
        help="List of images (regexp check) that will be handled",
        required=False,
        default=[])
    
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
        help="Will delete all tags. Overwrites keeping last 10 Tags.",
        const=True,
        default=False,
        action="store_const")
    
    parser.add_argument(
        '--layers',
        help=('Show layers digests for all images and all tags'),
        action='store_const',
        default=False,
        const=True)
    
    parser.add_argument(
        '--delete-by-hours',
        help=('Will delete all tags that are older than specified hours. Be careful!'),
        default=False,
        nargs='?',
        metavar='Hours')
    
    parser.add_argument(
        '--keep-by-hours',
        help=('Will keep all tags that are newer than specified hours.'
              'Do not use in combination with --delete-by-hours. Parameters control the same behavior.'),
        default=False,
        nargs='?',
        metavar='Hours')
    
    parser.add_argument(
        '--digest-method',
        help=('Use HEAD for standard docker registry or GET for NEXUS'),
        default='HEAD',
        metavar="HEAD|GET"
    )
    
    parser.add_argument(
         '--auth-method',
         help=('Use POST or GET to get JWT tokens'),
         default='POST',
         metavar="POST|GET"
    )
    
    parser.add_argument(
        '--order-by-date',
        help=('Orders images by date instead of by tag name.'
              'Useful if your tag names are not in a fixed order.'),
        action='store_true'
    )
    
    parser.add_argument(
        '--thread-limit',
        nargs='?',
        help='Limit parallel execution to defined number. Default 30.',
        required=False)
    
    parser.add_argument(
        '-f', '--force',
        help='If specified force delete digests with other tags that reference them.',
        action='store_const',
        default=False,
        const=True)
    return parser.parse_args(args)


def find_digests_to_delete(registry, image_name, tags_to_delete, tags_to_keep):
    print('---------------------------------')
    print("Getting digests for tags to keep:")
    keep_tag_digests = registry.get_keep_digests(image_name=image_name, tags_to_keep=tags_to_keep)
    print('---------------------------------')
    print("Getting digests for tags to delete:")
    delete_tag_digests = registry.get_delete_digests(image_name=image_name, tags_to_delete=tags_to_delete, digests_to_keep=keep_tag_digests)
    return delete_tag_digests


def delete_digests(registry, image_name,  dry_run, digests_to_delete):
    print('\n\n---------------------------------')
    if digests_to_delete:
        print("Start deleting digests.")
    else:
        print("Could not find any digest that can be deleted!")
        return
    print('---------------------------------')

    pool = ThreadPool(len(digests_to_delete))
    results = {}
    success = []
    failed = []
    deleted_digests = []
    failed_digests = []
    for digest in digests_to_delete:
        results[digest] = pool.apply_async(registry.delete_digest, args=(image_name, digest, dry_run))
    for digest in results.keys():
        result = results.get(digest)
        status, reason = result.get()
        if status:
            success.append(reason)
            deleted_digests.append(digest)
        else:
            failed.append(reason)
            failed_digests.append(digest)

    if deleted_digests:
        for message in success:
            print(message)
        if not dry_run:
            print("\nDeleted digests:")
            print('---------------------------------')
            for digest in deleted_digests:
                print(digest)

    if failed_digests:
        print("\nFailed to delete digests:")
        print('---------------------------------')
        for digest in failed_digests:
            print(digest)
        print('Errors:')
        for message in failed:
            print(message)

    pool.close()
    pool.join()


# :TODO: This function dose make sense. But, it should only delete specified tags without deleting other tags with same digest reference.
# def delete_tags(registry, image_name, dry_run, tags_to_delete, tags_to_keep):
#
#     keep_tag_digests = registry.get_keep_digests(image_name=image_name, tags_to_keep=tags_to_keep)
#     delete_tag_digests = registry.get_delete_digests(image_name=image_name, tags_to_delete=tags_to_delete, digests_to_keep=keep_tag_digests)
#
#     def delete(target_tag):
#         return registry.delete_digest_for_tag(image_name, target_tag, dry_run, keep_tag_digests, delete_tag_digests)
#
#     pool = ThreadPool(4)
#     results = {}
#     success = []
#     failed = []
#     for tag in tags_to_delete:
#         if tag in tags_to_keep:
#             continue
#         results[tag] = pool.apply_async(delete, args=(tag,))
#     for tag in results.keys():
#         result = results.get(tag)
#         status, reason = result.get()
#         if status:
#             success.append(reason)
#         else:
#             failed.append(reason)
#
#     print('---------------------------------')
#     for message in success:
#         print(message)
#
#     print('---------------------------------')
#     for message in failed:
#         print(message)
#
#     pool.close()
#     pool.join()

# deleting layers is disabled because
# it also deletes shared layers
##
# for layer in registry.list_tag_layers(image_name, tag):
# layer_digest = layer['digest']
# registry.delete_tag_layer(image_name, layer_digest, dry_run)


def get_tags_like(args_tags_like, tags_list):
    result = set()
    for tag_like in args_tags_like:
        if DEBUG:
            print("Tag like: {0}".format(tag_like))
        for tag in tags_list:
            if re.search(tag_like, tag):
                if DEBUG:
                    print("Adding {0} to tags list".format(tag))
                result.add(tag)
    return result


def get_tags_unlike(args_tags_like, tags_list):
    result = set()
    if DEBUG:
        print("Tags unlike: {0}".format(args_tags_like))
    for tag in tags_list:
        match = False
        for tag_like in args_tags_like:
            if re.search(tag_like, tag):
                match = True
                break
        if not match:
            if DEBUG:
                print("Adding {0} to keep tags list".format(tag))
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

    print('------------deleting-------------')
    delete_tags(registry, image_name, dry_run, tags_to_delete, tags_to_keep)


def get_newer_tags(registry, image_name, hours, tags_list):
    def newer(tag):
        image_config = registry.get_tag_config(image_name, tag)
        if not image_config:
            print("tag not found")
            return None
        image_age = registry.get_image_age(image_name, image_config)
        if not image_age:
            print("timestamp not found")
            return None
        if parse(image_age).astimezone(tzutc()) >= dt.now(tzutc()) - timedelta(hours=int(hours)):
            print("Newer tag: {0} timestamp: {1}".format(
                tag, image_age))
            return tag
        else:
            print("Older tag: {0} timestamp: {1}".format(
                tag, image_age))
            return None

    print('---------------------------------')
    pool = ThreadPool(limit_threads(tags_list))
    result = list(x for x in pool.map(newer, tags_list) if x)
    pool.close()
    pool.join()
    return result


def get_datetime_tags(registry, image_name, tags_list):
    def newer(tag):
        image_config = registry.get_tag_config(image_name, tag)
        if not image_config:
            print("tag not found")
            return None
        image_age = registry.get_image_age(image_name, image_config)
        if not image_age:
            print("timestamp not found")
            return None
        return {
            "tag": tag,
            "datetime": parse(image_age).astimezone(tzutc())
        }

    print('---------------------------------')
    pool = ThreadPool(limit_threads(tags_list))
    result = list(x for x in pool.map(newer, tags_list) if x)
    pool.close()
    pool.join()
    return result


def find_images_like(image_list, regexp_list):
    if image_list is None or regexp_list is None:
        return []
    result = []
    regexp_list = list(map(re.compile, regexp_list))
    for image in image_list:
        for regexp in regexp_list:
            if re.search(regexp, image):
                result.append(image)
                break
    return result


def get_ordered_tags(registry, image_name, tags_list, order_by_date=False):
    if order_by_date:
        tags_date = get_datetime_tags(registry, image_name, tags_list)
        sorted_tags_by_date = sorted(
            tags_date,
            key=lambda x: x["datetime"]
        )
        return [x["tag"] for x in sorted_tags_by_date]

    return sorted(tags_list, key=natural_keys)


def main_loop(args):
    global DEBUG
    global MAX_THREADS

    # Check parameter combination.
    if not args.num:
        keep_last_versions = CONST_KEEP_LAST_VERSIONS
    else:
        keep_last_versions = int(args.num)

    error = False
    if args.force and not args.tags_like:
        print("Parameter --tags-like is not defined, ignoring --force."
              "Because --force is additional parameter for --tags-like.")
    if args.num and args.delete_all:
        print("Combination of parameters --num and --delete-all is not allowed.")
        error = True
    if args.delete_by_hours and args.keep_by_hours:
        print("Combination of parameters --delete-by-hours and --keep-by-hours is not allowed."
              "Parameters --keep-by-hours is a substitute for --delete-by-hours.")
        error = True
    if error:
        exit(1)

    DEBUG = True if args.debug else False
    if args.thread_limit:
        MAX_THREADS = int(args.thread_limit)

    order_by_date = False

    delete = args.delete or args.delete_all or args.delete_by_hours
    if args.order_by_date or args.keep_by_hours or args.delete_by_hours:
        order_by_date = True

    if args.no_validate_ssl:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    if args.read_password:
        if args.login is None:
            print("Please provide -l when using -w")
            sys.exit(1)

        if ':' in args.login:
            (username, password) = args.login.split(':', 1)
        else:
            username = args.login

        if sys.stdin.isatty():
            # likely interactive usage
            password = getpass()

        else:
            # allow password to be piped or redirected in
            password = sys.stdin.read()

            if len(password) == 0:
                print("Password was not provided")
                sys.exit(1)

            if password[-(len(os.linesep)):] == os.linesep:
                password = password[0:-(len(os.linesep))]

        args.login = username + ':' + password

    registry = Registry.create(args.host, args.login, args.no_validate_ssl,
                               args.digest_method)

    registry.auth_schemes = get_auth_schemes(registry, '/v2/_catalog')

    if args.delete and not args.delete_all:
        print("Will keep last {0} tags independent from other search criteria.".format(keep_last_versions))

    if args.image is not None:
        image_list = args.image
    else:
        image_list = registry.list_images()
        if args.images_like:
            image_list = find_images_like(image_list, args.images_like)

    # loop through registry's images
    # or through the ones given in command line
    for image_name in image_list:
        print("---------------------------------")
        print("Image: {0}".format(image_name))

        all_tags_list = registry.list_tags(image_name)

        if not all_tags_list:
            print("  no tags found!")
            continue

        if args.tags_like:
            initial_tags_list = get_tags(all_tags_list, image_name, args.tags_like)

            tags_list = get_ordered_tags(registry=registry, image_name=image_name, tags_list=initial_tags_list, order_by_date=order_by_date)
            image_tags_header = "Tags like \"{0}\" found in image repository \"{1}\":".format(args.tags_like, image_name)
        else:
            tags_list = get_ordered_tags(registry=registry, image_name=image_name, tags_list=all_tags_list, order_by_date=order_by_date)
            image_tags_header = "All tags in image repository \"{0}\":".format(image_name)

        if tags_list:
            print(image_tags_header)
            print("---------------------------------")
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

        # add tags to "tags_to_keep" list, if we have regexp "tags_to_keep"
        # entries or a number of hours for "keep_by_hours":
        tag_list_to_keep = []

        if not delete:
            exit(0)

        print("\n\nStart filtering tags according to specified parameters:")
        if args.tags_like and not args.force:
            tag_list_to_keep.extend(get_tags_unlike(args.tags_like, all_tags_list))
        else:
            if args.keep_tags:
                tag_list_to_keep.extend(get_tags(args.keep_tags, image_name, all_tags_list))
            if args.keep_tags_like:
                tag_list_to_keep.extend(get_tags_like(args.keep_tags_like, all_tags_list))

        if args.keep_by_hours or args.delete_by_hours:
            hours = args.delete_by_hours or args.keep_by_hours
            tag_list_to_keep.extend(get_newer_tags(registry, image_name, hours, all_tags_list))

        if args.delete_all and not tag_list_to_keep:
            tags_list_to_delete = list(tags_list)
        else:
            ordered_tags_list = get_ordered_tags(registry, image_name, tags_list, order_by_date)
            if not args.delete_all:
                tags_list_to_delete = ordered_tags_list[:-keep_last_versions]
            else:
                tags_list_to_delete = ordered_tags_list

            # A manifest might be shared between different tags. Explicitly add those
            # tags that we want to preserve to the tag_list_to_keep list, to prevent
            # any manifest they are using from being deleted.
            tags_list_to_keep = [tag for tag in tags_list if tag not in tags_list_to_delete]
            tag_list_to_keep.extend(tags_list_to_keep)

        tag_list_to_keep = list(set(tag_list_to_keep))  # Eliminate duplicates

        if not tags_list_to_delete:
            print("\n\nNo tags with digest qualified for removal found in image repository \"{0}\":".format(image_name))
        else:
            if tag_list_to_keep:
                print("\n\n{0} tags shall be kept in image repository \"{1}\":".format(len(tag_list_to_keep), image_name))
                print("---------------------------------")
                for tag in tag_list_to_keep:
                    print("  tag: {0}".format(tag))
                    if args.layers:
                        for layer in registry.list_tag_layers(image_name, tag):
                            if 'size' in layer:
                                print("    layer: {0}, size: {1}".format(
                                    layer['digest'], layer['size']))
                            else:
                                print("    layer: {0}".format(
                                    layer['blobSum']))

            print("\n\n{0} tags can be removed from image repository \"{1}\":".format(len(tags_list_to_delete), image_name))
            print("---------------------------------")
            for tag in tags_list_to_delete:
                print("  tag: {0}".format(tag))
                if args.layers:
                    for layer in registry.list_tag_layers(image_name, tag):
                        if 'size' in layer:
                            print("    layer: {0}, size: {1}".format(
                                layer['digest'], layer['size']))
                        else:
                            print("    layer: {0}".format(
                                layer['blobSum']))
            print("\n\nChecking digest relationships:")
            print("---------------------------------")
            digests_to_delete = find_digests_to_delete(registry, image_name, tags_list_to_delete, tag_list_to_keep)
            delete_digests(registry, image_name, args.dry_run, digests_to_delete)


if __name__ == "__main__":
    args = parse_args()
    try:
        main_loop(args)
    except KeyboardInterrupt:
        print("Ctrl-C pressed, quitting")
        sys.exit(1)
