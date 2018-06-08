[![CircleCI](https://circleci.com/gh/andrey-pohilko/registry-cli/tree/master.svg?style=svg&circle-token=5216bf89763aec24bbcd6d15494ea32ffc53d66d)](https://circleci.com/gh/andrey-pohilko/registry-cli/tree/master)

# registry-cli
registry.py is a script for easy manipulation of docker-registry from command line (and from scripts)

## Table of Contents

* [Installation](#installation)
  * [Docker image](#docker-image)
  * [Python script](#python-script)
* [Listing images](#listing-images)
* [Username and password](#username-and-password)
* [Deleting images](#deleting-images)
* [Disable ssl verification](#disable-ssl-verification)
* [Nexus docker registry](#nexus-docker-registry)
* [Important notes](#important-notes)
  * [garbage-collection in docker-registry](#garbage-collection-in-docker-registry)
  * [enable image deletion in docker-registry](#enable-image-deletion-in-docker-registry)
* [Contribution](#contribution)

## Installation

### Docker image

You can download ready-made docker image with the script and all python dependencies pre-installed:

```
    docker pull anoxis/registry-cli
```

In this case, replace `registry.py` with `docker run --rm anoxis/registry-cli`
in all commands below, e.g.
```
    docker run --rm anoxis/registry-cli -r http://example.com:5000
```

Note: when you use the docker image and registry on the same computer (registry is on localhost), then due to internal network created by docker you have to link to the registry's network and refer registry container by its name, not localhost.
E.g. your registry container is named "registry",
then the command to launch registry-cli would be
```bash
    docker run --rm --link registry anoxis/registry-cli -r http://registry:5000
```
### python script

Download registry.py and set it as executable
```
  chmod 755 registry.py
```

Install dependencies:
```
  sudo pip install -r requirements-build.txt
```

## Listing images

The below command will list all images and all tags in your registry:
```
  registry.py -l user:pass -r https://example.com:5000
```

List all images, tags and layers:
```
  registry.py -l user:pass -r https://example.com:5000 --layers
```

List particular image(s) or image:tag (all tags of ubuntu and alpine in this example)
```
  registry.py -l user:pass -r https://example.com:5000 -i ubuntu alpine
```

Same as above but with layers
```
  registry.py -l user:pass -r https://example.com:5000 -i ubuntu alpine --layers
```

## Username and password

  It is optional, you can omit it in case if you use insecure registry without authentication (up to you,
  but its really insecure; make sure you protect your entire registry from anyone)

  username and password pair can be provided in the following forms
```
  -l username:password
  -l 'username':'password'
  -l "username":"password"
```
  Username cannot contain colon (':') (I don't think it will contain ever, but anyway I warned you).
  Password, in its turn, can contain as many colons as you wish.


## Deleting images

Keep only last 10 versions (useful for CI):
Delete all tags of all images but keep last 10 tags (you can put this command to your build script
after building images)
```
  registry.py -l user:pass -r https://example.com:5000 --delete
```
  If number of tags is less than 10 it will not delete any

You can change the number of tags to keep, e.g. 5:
```
  registry.py -l user:pass -r https://example.com:5000 --delete --num 5
```

You may also specify tags to be deleted using a list of regexp based names.
The following command would delete all tags containing "snapshot-" and beginning with "stable-" and a 4 digit number:

```
  registry.py -l user:pass -r https://example.com:5000 --delete --tags-like "snapshot-" "^stable-[0-9]{4}.*"
```

As one manifest may be referenced by more than one tag, you may add tags, whose manifests should NOT be deleted.
A tag that would otherwise be deleted, but whose manifest references one of those "kept" tags, is spared for deletion.
In the following case, all tags beginning with "snapshot-" will be deleted, save those whose manifest point to "stable" or "latest":

```
  registry.py -l user:pass -r https://example.com:5000 --delete --tags-like "snapshot-" --keep-tags "stable" "latest"
```
The last parameter is also available as regexp option with `--keep-tags-like`.


Delete all tags for particular image (e.g. delete all ubuntu tags):
```
  registry.py -l user:pass -r https://example.com:5000 -i ubuntu --delete-all
```

Delete all tags for all images (do you really want to do it?):
```
  registry.py -l user:pass -r https://example.com:5000 --delete-all --dry-run
```

Delete all tags by age in hours for the particular image (e.g. older than 24 hours, with `--keep-tags` and `--keep-tags-like` options, `--dry-run` for safe).
```
  registry.py -r https://example.com:5000 -i api-docs-origin/master --dry-run --delete-by-hours 24 --keep-tags c59c02c25f023263fd4b5d43fc1ff653f08b3d4x --keep-tags-like late
```

Note that deleting by age will not prevent more recent tags from being deleted if there are more than 10 (or specified `--num` value). In order to keep all tags within a designated period, use the `--keep-by-hours` flag:
```
  registry.py -r https://example.com:5000 --dry-run --delete --keep-by-hours 72 --keep-tags-like latest
```
## Disable ssl verification

If you are using docker registry with a self signed ssl certificate, you can disable ssl verification:
```
  registry.py -l user:pass -r https://example.com:5000 --no-validate-ssl
```

## Nexus docker registry

Add `--digest-method` flag

```
registry.py -l user:pass -r https://example.com:5000 --digest-method GET
```

## Important notes:

### garbage-collection in docker-registry
1. docker registry API does not actually delete tags or images, it marks them for later
garbage collection. So, make sure you run something like below
(or put them in your crontab):
```
  cd [path-where-your-docker-compose.yml]
  docker-compose stop registry
  docker-compose run --rm \
       registry bin/registry garbage-collect \
       /etc/docker/registry/config.yml
  docker-compose up -d registry
```
or (if you are not using docker-compose):
```
  docker stop registry:2
  docker run --rm registry:2 bin/registry garbage-collect \
       /etc/docker/registry/config.yml
  docker start registry:2
```
for more detail on garbage collection read here:
   https://docs.docker.com/registry/garbage-collection/

### enable image deletion in docker-registry
Make sure to enable it by either creating environment variable
  `REGISTRY_STORAGE_DELETE_ENABLED: "true"`
or adding relevant configuration option to the docker-registry's config.yml.
For more on docker-registry configuration, read here:
  https://docs.docker.com/registry/configuration/

You may get `Error 405` message from script (`Functionality not supported`) when this option is not enabled.


## Contribution
You are very welcome to contribute to this script. Of course, when making changes,
please include your changes into `test.py` and run tests to check that your changes
do not break existing functionality.

For tests to work, more libraries are needed
```
  pip install -r requirements-ci.txt
```

Running tests is as simple as
```
  python test.py
```

Test will print few error messages, like so
```
Testing started at 9:31 AM ...
  tag digest not found: 400
error 400
```
this is ok, because test simulates invalid inputs also.

# Contact

Please feel free to contact me at anoxis@gmail.com if you wish to add more functionality
or want to contribute.
