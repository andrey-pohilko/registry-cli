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
                auth=(None if self.username == ""
                    else (self.username, self.password)),
                verify=not self.no_validate_ssl)

        # except Exception as error:
        #     print("cannot connect to {0}\nerror {1}".format(
        #         self.hostname,
        #         error))
        #     sys.exit(1)
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

    # def list_tags_like(self, tag_like, args_tags_like):
    #     for tag_like in args_tags_like:
    #         print("tag like: {0}".format(tag_like))
    #         for tag in all_tags_list:
    #             if re.search(tag_like, tag):
    #                 print("Adding {0} to tags list".format(tag))

    def get_tag_digest(self, image_name, tag):
        image_headers = self.send("/v2/{0}/manifests/{1}".format(
            image_name, tag), method=self.digest_method)

        if image_headers is None:
            print("  tag digest not found: {0}.".format(self.last_error))
            print(get_error_explanation("get_tag_digest", self.last_error))
            return None

        tag_digest = image_headers.headers['Docker-Content-Digest']

        return tag_digest

    def delete_tag(self, image_name, tag, dry_run, tag_digests_to_ignore):
        if dry_run:
            print('would delete tag {0}'.format(tag))
            return False

        tag_digest = self.get_tag_digest(image_name, tag)

        if tag_digest in tag_digests_to_ignore:
            print("Digest {0} for tag {1} is referenced by another tag or has already been deleted and will be ignored".format(
                tag_digest, tag))
            return True

        if tag_digest is None:
            return False

        delete_result = self.send("/v2/{0}/manifests/{1}".format(
            image_name, tag_digest), method="DELETE")

        if delete_result is None:
            print("failed, error: {0}".format(self.last_error))
            print(get_error_explanation("delete_tag", self.last_error))
            return False

        tag_digests_to_ignore.append(tag_digest)

        print("done")
        return True


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
            print("Docker schemaVersion 1 isn't supported for deleting by age now")
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
        help=('If specified, delete all but last {0} tags '
              'of all images').format(CONST_KEEP_LAST_VERSIONS),
        action='store_const',
        default=False,
        const=True)

    parser.add_argument(
        '-n', '--num',
        help=('Set the number of tags to keep'
              '({0} if not set)').format(CONST_KEEP_LAST_VERSIONS),
        default=CONST_KEEP_LAST_VERSIONS,
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

    parser.add_argument(
        '--delete-by-hours',
        help=('Will delete all tags that are older than specified hours. Be careful!'),
        default=False,
        nargs='?',
        metavar='Hours')

    parser.add_argument(
        '--keep-by-hours',
        help=('Will keep all tags that are newer than specified hours.'),
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
                print("Tag {0} does not exist for image {1}. Ignore here.".format(
                    tag, image_name))
                continue

            print("Keep digest {0} for tag {1}".format(digest, tag))

            keep_tag_digests.append(digest)

    def delete(tag):
        print("  deleting tag {0}".format(tag))
        registry.delete_tag(image_name, tag, dry_run, keep_tag_digests)

    p = ThreadPool(4)
    tasks = []
    for tag in tags_to_delete:
        if tag in tags_to_keep:
            continue
        tasks.append(p.apply_async(delete, args=(tag,)))
    for task in tasks:
        task.get()
    p.close()
    p.join()

# deleting layers is disabled because
# it also deletes shared layers
##
# for layer in registry.list_tag_layers(image_name, tag):
# layer_digest = layer['digest']
# registry.delete_tag_layer(image_name, layer_digest, dry_run)


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


def delete_tags_by_age(registry, image_name, dry_run, hours, tags_to_keep):
    image_tags = registry.list_tags(image_name)
    tags_to_delete = []
    print('---------------------------------')
    for tag in image_tags:
        image_config = registry.get_tag_config(image_name, tag)

        if image_config == []:
            print("tag not found")
            continue

        image_age = registry.get_image_age(image_name, image_config)

        if image_age == []:
            print("timestamp not found")
            continue

        if parse(image_age).astimezone(tzutc()) < dt.now(tzutc()) - timedelta(hours=int(hours)):
            print("will be deleted tag: {0} timestamp: {1}".format(
                tag, image_age))
            tags_to_delete.append(tag)

    print('------------deleting-------------')
    delete_tags(registry, image_name, dry_run, tags_to_delete, tags_to_keep)


def get_newer_tags(registry, image_name, hours, tags_list):
    def newer(tag):
        image_config = registry.get_tag_config(image_name, tag)
        if image_config == []:
            print("tag not found")
            return None
        image_age = registry.get_image_age(image_name, image_config)
        if image_age == []:
            print("timestamp not found")
            return None
        if parse(image_age).astimezone(tzutc()) >= dt.now(tzutc()) - timedelta(hours=int(hours)):
            print("Keeping tag: {0} timestamp: {1}".format(
                tag, image_age))
            return tag
        else:
            print("Will delete tag: {0} timestamp: {1}".format(
                tag, image_age))
            return None

    print('---------------------------------')
    p = ThreadPool(4)
    result = list(x for x in p.map(newer, tags_list) if x)
    p.close()
    p.join()
    return result


def get_datetime_tags(registry, image_name, tags_list):
    def newer(tag):
        image_config = registry.get_tag_config(image_name, tag)
        if image_config == []:
            print("tag not found")
            return None
        image_age = registry.get_image_age(image_name, image_config)
        if image_age == []:
            print("timestamp not found")
            return None
        return {
            "tag": tag,
            "datetime": parse(image_age).astimezone(tzutc())
        }

    print('---------------------------------')
    p = ThreadPool(4)
    result = list(x for x in p.map(newer, tags_list) if x)
    p.close()
    p.join()
    return result


def keep_images_like(image_list, regexp_list):
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

    DEBUG = True if args.debug else False

    keep_last_versions = int(args.num)

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

    registry.auth_schemes = get_auth_schemes(registry,'/v2/_catalog')

    if args.delete:
        print("Will delete all but {0} last tags".format(keep_last_versions))

    if args.image is not None:
        image_list = args.image
    else:
        image_list = registry.list_images()
        if args.images_like:
            image_list = keep_images_like(image_list, args.images_like)

    # loop through registry's images
    # or through the ones given in command line
    for image_name in image_list:
        print("---------------------------------")
        print("Image: {0}".format(image_name))

        all_tags_list = registry.list_tags(image_name)

        if not all_tags_list:
            print("  no tags!")
            continue

        if args.order_by_date:
            tags_list = get_ordered_tags(registry, image_name, all_tags_list, args.order_by_date)
        else:
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

        # add tags to "tags_to_keep" list if we have regexp "tags_to_keep"
        # entries, a number of hours for "keep_by_hours" or if the user
        # explicitly specified tags to always keep.
        keep_tags = []
        keep_tags.extend(args.keep_tags)
        if args.keep_tags_like:
            keep_tags.extend(get_tags_like(args.keep_tags_like, tags_list))
        if args.keep_by_hours:
            keep_tags.extend(get_newer_tags(registry, image_name,
                                            args.keep_by_hours, tags_list))
        keep_tags = list(set(keep_tags))  # Eliminate duplicates

        # delete tags if told so
        if args.delete or args.delete_all:
            if args.delete_all:
                tags_list_to_delete = list(tags_list)
            else:
                ordered_tags_list = get_ordered_tags(registry, image_name, tags_list, args.order_by_date)
                tags_list_to_delete = ordered_tags_list[:-keep_last_versions]

                # A manifest might be shared between different tags. Explicitly add those
                # tags that we want to preserve to the keep_tags list, to prevent
                # any manifest they are using from being deleted.
                tags_list_to_keep = [
                    tag for tag in tags_list if tag not in tags_list_to_delete]
                keep_tags.extend(tags_list_to_keep)

            keep_tags.sort() # Make order deterministic for testing
            delete_tags(
                registry, image_name, args.dry_run,
                tags_list_to_delete, keep_tags)

        # delete tags by age in hours
        if args.delete_by_hours:
            delete_tags_by_age(registry, image_name, args.dry_run,
                               args.delete_by_hours, keep_tags)

if __name__ == "__main__":
    args = parse_args()
    try:
        main_loop(args)
    except KeyboardInterrupt:
        print("Ctrl-C pressed, quitting")
        sys.exit(1)
