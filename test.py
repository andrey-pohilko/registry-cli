import unittest

from datetime import datetime

from dateutil.tz import tzutc, tzoffset

from registry import Registry, Requests, get_tags, parse_args, \
    delete_tags, delete_tags_by_age, get_error_explanation, get_newer_tags, \
    keep_images_like, main_loop, get_datetime_tags, get_ordered_tags
from mock import MagicMock, patch
import requests


class ReturnValue:

    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class MockRequests:

    def __init__(self, return_value=ReturnValue()):
        self.return_value = return_value
        self.request = MagicMock(return_value=self.return_value)

    def reset_return_value(self, status_code=200, text=""):
        self.return_value.status_code = status_code
        self.return_value.text = text


class TestRequestsClass(unittest.TestCase):

    def test_requests_created(self):
        # simply create requests class and make sure it raises an exception
        # from requests module
        # this test will fail if port 45272 is open on local machine
        # is so, either change port below or check what is this service you are
        # running on port 45272
        with self.assertRaises(requests.exceptions.ConnectionError):
            Requests().request("GET", "http://localhost:45272")


class TestCreateMethod(unittest.TestCase):

    def test_create_nologin(self):
        r = Registry.create("testhost", None, False)
        self.assertTrue(isinstance(r.http, Requests))
        self.assertEqual(r.hostname, "testhost")
        self.assertEqual(r.no_validate_ssl, False)

    def test_create_login(self):
        r = Registry.create("testhost2", "testlogin:testpass", False)
        self.assertEqual(r.hostname, "testhost2")
        self.assertTrue(isinstance(r.http, Requests))
        self.assertEqual(r.username, "testlogin")
        self.assertEqual(r.password, "testpass")

    def test_validate_ssl(self):
        r = Registry.create("testhost3", None, True)
        self.assertTrue(isinstance(r.http, Requests))
        self.assertTrue(r.no_validate_ssl)
        self.assertEqual(r.username, None)
        self.assertEqual(r.password, None)

    def test_invalid_login(self):
        with self.assertRaises(SystemExit):
            Registry.create("testhost4", "invalid_login", False)


class TestParseLogin(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()

    def test_login_args_ok(self):
        (username, password) = self.registry.parse_login("username:password")
        self.assertEqual(username, "username")
        self.assertEqual(password, "password")
        self.assertEqual(self.registry.last_error, None)

    def test_login_args_double_colon(self):
        (username, password) = self.registry.parse_login("username:pass:word")
        self.assertEqual(username, "username")
        self.assertEqual(password, "pass:word")
        self.assertEqual(self.registry.last_error, None)

    # this test becomes reduntant
    def test_login_args_no_colon(self):
        (username, password) = self.registry.parse_login("username/password")
        self.assertEqual(username, None)
        self.assertEqual(password, None)
        self.assertEqual(self.registry.last_error,
                         "Please provide -l in the form USER:PASSWORD")

    def test_login_args_singlequoted(self):
        (username, password) = self.registry.parse_login("'username':password")
        self.assertEqual(username, 'username')
        self.assertEqual(password, "password")
        self.assertEqual(self.registry.last_error, None)

    def test_login_args_doublequoted(self):
        (username, password) = self.registry.parse_login('"username":"password"')
        self.assertEqual(username, 'username')
        self.assertEqual(password, "password")
        self.assertEqual(self.registry.last_error, None)

    def test_login_colon_username(self):
        """
        this is to test that if username contains colon,
        then the result will be invalid in this case
        and no error will be printed
        """
        (username, password) = self.registry.parse_login(
            "'user:name':'pass:word'")
        self.assertEqual(username, 'user')
        self.assertEqual(password, "name':'pass:word")


class TestRegistrySend(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"

    def test_get_ok(self):
        self.registry.http.reset_return_value(200)
        response = self.registry.send('/test_string')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.registry.last_error, None)
        self.registry.http.request.assert_called_with('GET',
                                                      'http://testdomain.com/test_string',
                                                      auth=(None, None),
                                                      headers=self.registry.HEADERS,
                                                      verify=True)

    def test_invalid_status_code(self):
        self.registry.http.reset_return_value(400)
        response = self.registry.send('/v2/catalog')
        self.assertEqual(response, None)
        self.assertEqual(self.registry.last_error, 400)

    def test_login_pass(self):
        self.registry.username = "test_login"
        self.registry.password = "test_password"
        self.registry.http.reset_return_value(200)
        response = self.registry.send('/v2/catalog')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.registry.last_error, None)
        self.registry.http.request.assert_called_with('GET',
                                                      'http://testdomain.com/v2/catalog',
                                                      auth=("test_login",
                                                            "test_password"),
                                                      headers=self.registry.HEADERS,
                                                      verify=True)

class TestGetErrorExplanation(unittest.TestCase):
    def test_get_tag_digest_404(self):
        self.assertEqual(get_error_explanation("delete_tag", "405"),
                         'You might want to set REGISTRY_STORAGE_DELETE_ENABLED: "true" in your registry')

    def test_delete_digest_405(self):
        self.assertEqual(get_error_explanation("get_tag_digest", "404"),
                         "Try adding flag --digest-method=GET")


class TestListImages(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"

    def test_list_images_ok(self):
        self.registry.http.reset_return_value(status_code=200,
                                              text='{"repositories":["image1","image2"]}')
        response = self.registry.list_images()
        self.assertEqual(response, ["image1", "image2"])
        self.assertEqual(self.registry.last_error, None)

    def test_list_images_invalid_http_response(self):
        self.registry.http.reset_return_value(404)
        response = self.registry.list_images()
        self.assertEqual(response, [])
        self.assertEqual(self.registry.last_error, 404)


class TestListTags(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200)

    def test_list_one_tag_ok(self):
        self.registry.http.reset_return_value(status_code=200,
                                              text=u'{"name":"image1","tags":["0.1.306"]}')

        response = self.registry.list_tags('image1')
        self.assertEqual(response, ["0.1.306"])
        self.assertEqual(self.registry.last_error, None)

    def test_list_tags_invalid_http_response(self):
        self.registry.http.reset_return_value(status_code=400,
                                              text="")

        response = self.registry.list_tags('image1')
        self.assertEqual(response, [])
        self.assertEqual(self.registry.last_error, 400)

    def test_list_tags_invalid_json(self):
        self.registry.http.reset_return_value(status_code=200,
                                              text="invalid_json")

        response = self.registry.list_tags('image1')
        self.assertEqual(response, [])
        self.assertEqual(self.registry.last_error,
                         "list_tags: invalid json response")

    def test_list_one_tag_sorted(self):
        self.registry.http.reset_return_value(status_code=200,
                                              text=u'{"name":"image1","tags":["0.1.306", "0.1.300", "0.1.290"]}')

        response = self.registry.list_tags('image1')
        self.assertEqual(response, ["0.1.290", "0.1.300", "0.1.306"])
        self.assertEqual(self.registry.last_error, None)

    def test_list_tags_like_various(self):
        tags_list = set(['FINAL_0.1', 'SNAPSHOT_0.1',
                         "0.1.SNAP", "1.0.0_FINAL"])
        for plain in [True, False]:
            self.assertEqual(get_tags(tags_list, "", set(
                ["FINAL"]), plain), set(["FINAL_0.1", "1.0.0_FINAL"]))
            self.assertEqual(get_tags(tags_list, "", set(
                ["SNAPSHOT"]), plain), set(['SNAPSHOT_0.1']))
            self.assertEqual(get_tags(tags_list, "", set(), plain),
                            set(['FINAL_0.1', 'SNAPSHOT_0.1', "0.1.SNAP", "1.0.0_FINAL"]))
            self.assertEqual(get_tags(tags_list, "", set(["ABSENT"]), plain), set())
            self.assertEqual(
                get_tags(tags_list, "IMAGE:TAG00", "", plain), set(["TAG00"]))
            self.assertEqual(get_tags(tags_list, "IMAGE:TAG00", set(
                ["WILL_NOT_BE_CONSIDERED"]), plain), set(["TAG00"]))


class TestListDigest(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200)

    def test_get_digest_ok(self):
        self.registry.http.reset_return_value(status_code=200,
                                              text=('{'
                                                    '"schemaVersion": 2,\n '
                                                    '"mediaType": "application/vnd.docker.distribution.manifest.v2+json"'
                                                    '"digest": "sha256:357ea8c3d80bc25792e010facfc98aee5972ebc47e290eb0d5aea3671a901cab"'
                                                    ))

        self.registry.http.return_value.headers = {
            'Content-Length': '4935',
            'Docker-Content-Digest': 'sha256:85295b0e7456a8fbbc886722b483f87f2bff553fa0beeaf37f5d807aff7c1e52',
            'X-Content-Type-Options': 'nosniff'
        }

        response = self.registry.get_tag_digest('image1', '0.1.300')
        self.registry.http.request.assert_called_with(
            "HEAD",
            "http://testdomain.com/v2/image1/manifests/0.1.300",
            auth=(None, None),
            headers=self.registry.HEADERS,
            verify=True
        )

        self.assertEqual(
            response, 'sha256:85295b0e7456a8fbbc886722b483f87f2bff553fa0beeaf37f5d807aff7c1e52')
        self.assertEqual(self.registry.last_error, None)

    def test_get_digest_nexus_ok(self):
        self.registry.http.reset_return_value(status_code=200,
                                              text=('{'
                                                    '"schemaVersion": 2,\n '
                                                    '"mediaType": "application/vnd.docker.distribution.manifest.v2+json"'
                                                    '"digest": "sha256:357ea8c3d80bc25792e010facfc98aee5972ebc47e290eb0d5aea3671a901cab"'
                                                    ))

        self.registry.http.return_value.headers = {
            'Content-Length': '4935',
            'Docker-Content-Digest': 'sha256:85295b0e7456a8fbbc886722b483f87f2bff553fa0beeaf37f5d807aff7c1e52',
            'X-Content-Type-Options': 'nosniff'
        }

        self.registry.digest_method = "GET"
        response = self.registry.get_tag_digest('image1', '0.1.300')
        self.registry.http.request.assert_called_with(
            "GET",
            "http://testdomain.com/v2/image1/manifests/0.1.300",
            auth=(None, None),
            headers=self.registry.HEADERS,
            verify=True
        )

        self.assertEqual(
            response, 'sha256:85295b0e7456a8fbbc886722b483f87f2bff553fa0beeaf37f5d807aff7c1e52')
        self.assertEqual(self.registry.last_error, None)


    def test_invalid_status_code(self):
        self.registry.http.reset_return_value(400)
        response = self.registry.get_tag_digest('image1', '0.1.300')
        self.assertEqual(response, None)

    def test_invalid_headers(self):
        self.registry.http.reset_return_value(200, "invalid json")
        self.registry.http.return_value.headers = "invalid headers"
        with self.assertRaises(TypeError):
            self.registry.get_tag_digest('image1', '0.1.300')


class TestTagConfig(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200)

    def test_get_tag_config_ok(self):
        self.registry.http.reset_return_value(
            200,
            '''
                {
                  "schemaVersion": 2,
                  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                  "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": 12953,
                    "digest": "sha256:8d71dfbf239c0015ad66993d55d3954cee2d52d86f829fdff9ccfb9f23b75aa8"
                  },
                  "layers": [
                    {
                      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                      "size": 51480140,
                      "digest": "sha256:c6b13209f43b945816b7658a567720983ac5037e3805a779d5772c61599b4f73"
                    }
                   ]
                }
            '''
        )

        response = self.registry.get_tag_config('image1', '0.1.300')

        self.registry.http.request.assert_called_with(
            "GET",
            "http://testdomain.com/v2/image1/manifests/0.1.300",
            auth=(None, None),
            headers=self.registry.HEADERS,
            verify=True)

        self.assertEqual(
            response, {'mediaType': 'application/vnd.docker.container.image.v1+json', 'size': 12953, 'digest': 'sha256:8d71dfbf239c0015ad66993d55d3954cee2d52d86f829fdff9ccfb9f23b75aa8'})
        self.assertEqual(self.registry.last_error, None)

    def test_tag_config_scheme_v1(self):
        with self.assertRaises(SystemExit):
            self.registry.http.reset_return_value(
                200,
                '''
                {
                  "schemaVersion": 1
                }
            '''
            )
            response = self.registry.get_tag_config('image1', '0.1.300')

    def test_invalid_status_code(self):
        self.registry.http.reset_return_value(400, "whatever")

        response = self.registry.get_tag_config('image1', '0.1.300')

        self.registry.http.request.assert_called_with(
            "GET",
            "http://testdomain.com/v2/image1/manifests/0.1.300",
            auth=(None, None),
            headers=self.registry.HEADERS,
            verify=True
        )

        self.assertEqual(response, [])
        self.assertEqual(self.registry.last_error, 400)


class TestImageAge(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200)

    def test_image_age_ok(self):
        self.registry.http.reset_return_value(
            200,
            '''
                {
                  "architecture": "amd64",
                  "author": "Test",
                  "config": {},
                  "container": "c467822c5981cd446068eebafd81cb5cde60d4341a945f3fbf67e456dde5af51",
                  "container_config": {},
                  "created": "2017-12-27T12:47:33.511765448Z",
                  "docker_version": "1.11.2",
                  "history": []
                }
            '''
        )
        json_payload = {'mediaType': 'application/vnd.docker.container.image.v1+json', 'size': 12953,
                        'digest': 'sha256:8d71dfbf239c0015ad66993d55d3954cee2d52d86f829fdff9ccfb9f23b75aa8'}
        header = {"Accept": "{0}".format(json_payload['mediaType'])}
        response = self.registry.get_image_age('image1', json_payload)

        self.registry.http.request.assert_called_with(
            "GET",
            "http://testdomain.com/v2/image1/blobs/sha256:8d71dfbf239c0015ad66993d55d3954cee2d52d86f829fdff9ccfb9f23b75aa8",
            auth=(None, None),
            headers=header,
            verify=True)

        self.assertEqual(
            response, "2017-12-27T12:47:33.511765448Z")
        self.assertEqual(self.registry.last_error, None)

    def test_image_age_nok(self):
        self.registry.http.reset_return_value(400, "err")
        json_payload = {'mediaType': 'application/vnd.docker.container.image.v1+json', 'size': 12953,
                        'digest': 'sha256:8d71dfbf239c0015ad66993d55d3954cee2d52d86f829fdff9ccfb9f23b75aa8'}
        header = {"Accept": "{0}".format(json_payload['mediaType'])}
        response = self.registry.get_image_age('image1', json_payload)

        self.registry.http.request.assert_called_with(
            "GET",
            "http://testdomain.com/v2/image1/blobs/sha256:8d71dfbf239c0015ad66993d55d3954cee2d52d86f829fdff9ccfb9f23b75aa8",
            auth=(None, None),
            headers=header,
            verify=True)

        self.assertEqual(response, [])
        self.assertEqual(self.registry.last_error, 400)


class TestListLayers(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200)

    def test_list_layers_schema_version_2_ok(self):
        self.registry.http.reset_return_value(
            200,
            '''
            {
                "schemaVersion": 2,
                "layers": "layers_list"
            }
            '''
        )

        response = self.registry.list_tag_layers('image1', '0.1.300')

        self.registry.http.request.assert_called_with(
            "GET",
            "http://testdomain.com/v2/image1/manifests/0.1.300",
            auth=(None, None),
            headers=self.registry.HEADERS,
            verify=True
        )

        self.assertEqual(response, "layers_list")
        self.assertEqual(self.registry.last_error, None)

    def test_list_layers_schema_version_1_ok(self):
        self.registry.http.reset_return_value(
            200,
            '''
            {
                "schemaVersion": 1,
                "fsLayers": "layers_list"
            }
            '''
        )

        response = self.registry.list_tag_layers('image1', '0.1.300')

        self.registry.http.request.assert_called_with(
            "GET",
            "http://testdomain.com/v2/image1/manifests/0.1.300",
            auth=(None, None),
            headers=self.registry.HEADERS,
            verify=True
        )

        self.assertEqual(response, "layers_list")
        self.assertEqual(self.registry.last_error, None)

    def test_list_layers_invalid_status_code(self):
        self.registry.http.reset_return_value(400, "whatever")

        response = self.registry.list_tag_layers('image1', '0.1.300')

        self.registry.http.request.assert_called_with(
            "GET",
            "http://testdomain.com/v2/image1/manifests/0.1.300",
            auth=(None, None),
            headers=self.registry.HEADERS,
            verify=True
        )

        self.assertEqual(response, [])
        self.assertEqual(self.registry.last_error, 400)


class TestDeletion(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200, "MOCK_DIGEST")
        self.registry.http.return_value.headers = {
            'Content-Length': '4935',
            'Docker-Content-Digest': 'MOCK_DIGEST_HEADER',
            'X-Content-Type-Options': 'nosniff'
        }

    def test_delete_tag_dry_run(self):
        response = self.registry.delete_tag("image1", 'test_tag', True, [])
        self.assertFalse(response)

    def test_delete_tag_ok(self):
        keep_tag_digests = ['DIGEST1', 'DIGEST2']
        response = self.registry.delete_tag(
            'image1', 'test_tag', False, keep_tag_digests)
        self.assertEqual(response, True)
        self.assertEqual(self.registry.http.request.call_count, 2)
        self.registry.http.request.assert_called_with(
            "DELETE",
            "http://testdomain.com/v2/image1/manifests/MOCK_DIGEST_HEADER",
            auth=(None, None),
            headers=self.registry.HEADERS,
            verify=True
        )
        self.assertTrue("MOCK_DIGEST_HEADER" in keep_tag_digests)

    def test_delete_tag_ignored(self):
        response = self.registry.delete_tag(
            'image1', 'test_tag', False, ['MOCK_DIGEST_HEADER'])
        self.assertEqual(response, True)
        self.assertEqual(self.registry.http.request.call_count, 1)
        self.registry.http.request.assert_called_with(
            "HEAD",
            "http://testdomain.com/v2/image1/manifests/test_tag",
            auth=(None, None),
            headers=self.registry.HEADERS,
            verify=True
        )

    def test_delete_tag_no_digest(self):
        self.registry.http.reset_return_value(400, "")
        response = self.registry.delete_tag('image1', 'test_tag', False, [])
        self.assertFalse(response)
        self.assertEqual(self.registry.last_error, 400)


class TestDeleteTagsFunction(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.delete_mock = MagicMock()
        self.registry.delete_tag = self.delete_mock
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200, "MOCK_DIGEST")
        self.registry.http.return_value.headers = {
            'Content-Length': '4935',
            'Docker-Content-Digest': 'MOCK_DIGEST_HEADER',
            'X-Content-Type-Options': 'nosniff'
        }

    def test_delete_tags_no_keep(self):
        delete_tags(self.registry, "imagename", False, ["tag_to_delete"], [])
        self.delete_mock.assert_called_with(
            "imagename",
            "tag_to_delete",
            False,
            []
        )

    def test_delete_tags_keep(self):
        digest_mock = MagicMock(return_value="DIGEST_MOCK")
        self.registry.get_tag_digest = digest_mock

        delete_tags(self.registry, "imagename",
                    False, ["tag1", "tag2"], ["tag2"])

        digest_mock.assert_called_with("imagename", "tag2")

        self.delete_mock.assert_called_with(
            "imagename",
            "tag1",
            False,
            ['DIGEST_MOCK']
        )

    def test_delete_tags_digest_none(self):
        digest_mock = MagicMock(return_value=None)
        self.registry.get_tag_digest = digest_mock
        delete_tags(self.registry, "imagename",
                    False, ["tag1", "tag2"], ["tag2"])

        digest_mock.assert_called_with("imagename", "tag2")

        self.delete_mock.assert_called_with(
            "imagename",
            "tag1",
            False,
            []
        )


class TestDeleteTagsByAge(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()

        self.get_tag_config_mock = MagicMock(return_value={'mediaType': 'application/vnd.docker.container.image.v1+json', 'size': 12953,
                                                           'digest': 'sha256:8d71dfbf239c0015ad66993d55d3954cee2d52d86f829fdff9ccfb9f23b75aa8'})
        self.registry.get_tag_config = self.get_tag_config_mock
        self.get_image_age_mock = MagicMock(
            return_value="2017-12-27T12:47:33.511765448Z")
        self.registry.get_image_age = self.get_image_age_mock
        self.list_tags_mock = MagicMock(return_value=["image"])
        self.registry.list_tags = self.list_tags_mock
        self.get_tag_digest_mock = MagicMock()
        self.registry.get_tag_digest = self.get_tag_digest_mock
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200, "MOCK_DIGEST")

    @patch('registry.delete_tags')
    def test_delete_tags_by_age_no_keep(self, delete_tags_patched):
        delete_tags_by_age(self.registry, "imagename", False, 24, [])
        self.list_tags_mock.assert_called_with(
            "imagename"
        )
        self.list_tags_mock.assert_called_with("imagename")
        self.get_tag_config_mock.assert_called_with("imagename", "image")
        delete_tags_patched.assert_called_with(
            self.registry, "imagename", False, ["image"], [])

    @patch('registry.delete_tags')
    def test_delete_tags_by_age_no_keep_with_non_utc_value(self, delete_tags_patched):
        self.registry.get_image_age.return_value = "2017-12-27T12:47:33.511765448+02:00"
        delete_tags_by_age(self.registry, "imagename", False, 24, [])
        self.list_tags_mock.assert_called_with(
            "imagename"
        )
        self.list_tags_mock.assert_called_with("imagename")
        self.get_tag_config_mock.assert_called_with("imagename", "image")
        delete_tags_patched.assert_called_with(
            self.registry, "imagename", False, ["image"], [])

    @patch('registry.delete_tags')
    def test_delete_tags_by_age_keep_tags(self, delete_tags_patched):
        delete_tags_by_age(self.registry, "imagename", False, 24, ["latest"])
        self.list_tags_mock.assert_called_with(
            "imagename"
        )
        self.list_tags_mock.assert_called_with("imagename")
        self.get_tag_config_mock.assert_called_with("imagename", "image")
        delete_tags_patched.assert_called_with(
            self.registry, "imagename", False, ["image"], ["latest"])

    @patch('registry.delete_tags')
    def test_delete_tags_by_age_dry_run(self, delete_tags_patched):
        delete_tags_by_age(self.registry, "imagename", True, 24, ["latest"])
        self.list_tags_mock.assert_called_with(
            "imagename"
        )
        self.list_tags_mock.assert_called_with("imagename")
        self.get_tag_config_mock.assert_called_with("imagename", "image")
        delete_tags_patched.assert_called_with(
            self.registry, "imagename", True, ["image"], ["latest"])


class TestGetNewerTags(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()

        self.get_tag_config_mock = MagicMock(return_value={'mediaType': 'application/vnd.docker.container.image.v1+json', 'size': 12953,
                                                           'digest': 'sha256:8d71dfbf239c0015ad66993d55d3954cee2d52d86f829fdff9ccfb9f23b75aa8'})
        self.registry.get_tag_config = self.get_tag_config_mock
        self.get_image_age_mock = MagicMock(
            return_value="2017-12-27T12:47:33.511765448Z")
        self.registry.get_image_age = self.get_image_age_mock
        self.list_tags_mock = MagicMock(return_value=["image"])
        self.registry.list_tags = self.list_tags_mock
        self.get_tag_digest_mock = MagicMock()
        self.registry.get_tag_digest = self.get_tag_digest_mock
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200, "MOCK_DIGEST")

        def test_keep_tags_by_age_no_keep(self):
            self.assertEqual(
                get_newer_tags(self.registry, "imagename", 23, ["latest"]),
                []
            )

        def test_keep_tags_by_age_keep(self):
            self.assertEqual(
                get_newer_tags(self.registry, "imagename", 24, ["latest"]),
                ["latest"]
            )

        def test_keep_tags_by_age_no_keep_non_utc_datetime(self):
            self.registry.get_image_age.return_value = "2017-12-27T12:47:33.511765448+02:00"
            self.assertEqual(
                get_newer_tags(self.registry, "imagename", 23, ["latest"]),
                []
            )


class TestGetDatetimeTags(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = MockRequests()

        self.get_tag_config_mock = MagicMock(return_value={'mediaType': 'application/vnd.docker.container.image.v1+json', 'size': 12953,
                                                           'digest': 'sha256:8d71dfbf239c0015ad66993d55d3954cee2d52d86f829fdff9ccfb9f23b75aa8'})
        self.registry.get_tag_config = self.get_tag_config_mock
        self.get_image_age_mock = MagicMock(
            return_value="2017-12-27T12:47:33.511765448Z")
        self.registry.get_image_age = self.get_image_age_mock
        self.list_tags_mock = MagicMock(return_value=["image"])
        self.registry.list_tags = self.list_tags_mock
        self.get_tag_digest_mock = MagicMock()
        self.registry.get_tag_digest = self.get_tag_digest_mock
        self.registry.http = MockRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200, "MOCK_DIGEST")

    def test_get_datetime_tags(self):
        for plain in [True, False]:
            self.assertEqual(
                get_datetime_tags(self.registry, "imagename", ["latest"], plain),
                [{"tag": "latest", "datetime": datetime(2017, 12, 27, 12, 47, 33, 511765, tzinfo=tzutc())}]
            )

    def test_get_non_utc_datetime_tags(self):
        self.registry.get_image_age.return_value = "2019-07-18T16:33:15.864962122+02:00"
        for plain in [True, False]:
            self.assertEqual(
                get_datetime_tags(self.registry, "imagename", ["latest"], plain),
                [{"tag": "latest", "datetime": datetime(2019, 7, 18, 16, 33, 15, 864962, tzinfo=tzoffset(None, 7200))}]
            )


class TestGetOrderedTags(unittest.TestCase):
    def setUp(self):
        self.tags = ["e61d48b", "ff24a83", "ddd514c", "f4ba381", "9d5fab2"]

    def test_tags_are_ordered_by_name_by_default(self):
        tags = ["v1", "v10", "v2"]
        ordered_tags = get_ordered_tags(registry=None, image_name=None, tags_list=tags)
        self.assertEqual(ordered_tags, ["v1", "v2", "v10"])

    @patch('registry.get_datetime_tags')
    def test_tags_are_ordered_ascending_by_date_if_the_option_is_given(self, get_datetime_tags_patched):
        tags = ["e61d48b", "ff24a83", "ddd514c", "f4ba381", "9d5fab2"]
        get_datetime_tags_patched.return_value = [
            {
                "tag": "e61d48b",
                "datetime": datetime(2025, 1, 1, tzinfo=tzutc())
            },
            {
                "tag": "ff24a83",
                "datetime": datetime(2024, 1, 1, tzinfo=tzutc())
            },
            {
                "tag": "ddd514c",
                "datetime": datetime(2023, 1, 1, tzinfo=tzutc())
            },
            {
                "tag": "f4ba381",
                "datetime": datetime(2022, 1, 1, tzinfo=tzutc())
            },
            {
                "tag": "9d5fab2",
                "datetime": datetime(2021, 1, 1, tzinfo=tzutc())
            }
        ]
        ordered_tags = get_ordered_tags(registry="registry", image_name="image", tags_list=tags, order_by_date=True)
        get_datetime_tags_patched.assert_called_once_with("registry", "image", tags)
        self.assertEqual(ordered_tags, ["9d5fab2", "f4ba381", "ddd514c", "ff24a83", "e61d48b"])


class TestKeepImagesLike(unittest.TestCase):

    # tests the filtering works
    def test_keep_images_like(self):
        self.images = ["lorem", "ipsum", "dolor", "sit", "amet"]
        self.assertEqual(keep_images_like(self.images, ["bad"]), [])
        self.assertEqual(keep_images_like(self.images, ["lorem"]), ["lorem"])
        self.assertEqual(keep_images_like(self.images, ["lorem", "ipsum"]), ["lorem", "ipsum"])
        self.assertEqual(keep_images_like(self.images, ["i"]), ["ipsum", "sit"])
        self.assertEqual(keep_images_like(self.images, ["^i"]), ["ipsum"])
        self.assertEqual(keep_images_like([], ["^i"]), [])
        self.assertEqual(keep_images_like(self.images, []), [])
        self.assertEqual(keep_images_like([], []), [])
        self.assertEqual(keep_images_like(None, None), [])

    # mock Registry.create that sets things up
    # we need this because we want to call main_loop
    # which creates the Registry object by itself calling create
    @staticmethod
    def mock_create(h, l, n, d="HEAD"):
        r = Registry._create(h, l, n, d)
        r.http = MockRequests()
        r.list_images = MagicMock(return_value=['a', 'b', 'c'])
        return r

    @patch('registry.Registry.create', mock_create)
    @patch('registry.get_auth_schemes')  # called in main_loop, turn to noop
    @patch('registry.keep_images_like')
    def test_main_calls(self, keep_images_like_patched, get_auth_schemes_patched):
        # check if keep_images_like is called when passed --images-like
        main_loop(parse_args(('-r', 'localhost:8989', '--images-like', 'me')))
        keep_images_like_patched.assert_called_with(['a', 'b', 'c'], ['me'])

        # check if keep_images_like is *not* called when passed --images-like
        keep_images_like_patched.reset_mock()
        args = parse_args(('-r', 'localhost:8989'))
        args.image = []  # this makes the for loop in main_loop not run at all
        main_loop(args)
        keep_images_like_patched.assert_not_called()


class TestKeepTags(unittest.TestCase):
    @staticmethod
    def create_mock_registry(host, login, no_validate_ssl, digest_method="HEAD"):
        r = Registry._create(host, login, no_validate_ssl, digest_method)
        r.http = MockRequests()
        r.list_images = MagicMock(return_value=['a'])
        r.list_tags = MagicMock(return_value=['1', '2', '3', '4', '5', '6', '7'])
        return r

    # We store the actual mock registry here so we can later compare it in
    # `assert_called_with()`.
    mock_registry = create_mock_registry.__func__('localhost:8989', None, True)

    def return_mock_registry(self, host, login, no_validate_ssl, digest_method="HEAD"):
        return TestKeepTags.mock_registry

    @patch('registry.Registry.create', return_mock_registry)
    @patch('registry.get_auth_schemes')  # called in main_loop, turn to noop
    @patch('registry.delete_tags')
    def test_keep_tags(self, delete_tags_patched, get_auth_schemes_patched):
        # Check if delete_tags is called from main_loop (directly or indirectly
        # through delete_tags_by_age) with `keep_tags` set to the tags we want to keep.
        main_loop(parse_args(('--delete', '--num', '5', '-r', 'localhost:8989', '--keep-tags', '1')))
        delete_tags_patched.assert_called_with(TestKeepTags.mock_registry, 'a', False, ['1', '2'], ['1', '3', '4', '5', '6', '7'])


class TestArgParser(unittest.TestCase):

    def test_no_args(self):
        with self.assertRaises(SystemExit):
            parse_args("")

    def test_all_args(self):
        args_list = ["-r", "hostname",
                     "-l", "loginstring",
                     "-d",
                     "-n", "15",
                     "--dry-run",
                     "-i", "imagename1", "imagename2",
                     "--keep-tags", "keep1", "keep2",
                     "--tags-like", "tags_like_text",
                     "--no-validate-ssl",
                     "--delete-all",
                     "--layers",
                     "--delete-by-hours", "24",
                     "--keep-by-hours", "24",
                     "--digest-method", "GET",
                     "--order-by-date"]
        args = parse_args(args_list)
        self.assertTrue(args.delete)
        self.assertTrue(args.layers)
        self.assertTrue(args.no_validate_ssl)
        self.assertTrue(args.delete_all)
        self.assertTrue(args.layers)
        self.assertTrue(args.order_by_date)
        self.assertEqual(args.image, ["imagename1", "imagename2"])
        self.assertEqual(args.num, "15")
        self.assertEqual(args.login, "loginstring")
        self.assertEqual(args.tags_like, ["tags_like_text"])
        self.assertEqual(args.host, "hostname")
        self.assertEqual(args.keep_tags, ["keep1", "keep2"])
        self.assertEqual(args.delete_by_hours, "24")
        self.assertEqual(args.keep_by_hours, "24")
        self.assertEqual(args.digest_method, "GET")

    def test_default_args(self):
        args_list = ["-r", "hostname",
                     "-l", "loginstring"]
        args = parse_args(args_list)
        self.assertEqual(args.digest_method, "HEAD")
        self.assertFalse(args.order_by_date)


if __name__ == '__main__':
    unittest.main()
