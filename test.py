import unittest
from registry import Registry
from mock import MagicMock


class ReturnValue:
    def __init__(self, status_code = 200, text = ""):
        self.status_code = status_code
        self.text = text


class TestRequests:

    def __init__(self, return_value = ReturnValue()):
        self.return_value = return_value
        self.request = MagicMock(return_value = self.return_value)

    def reset_return_value(self, status_code = 200, text = ""):
        self.return_value.status_code = status_code
        self.return_value.text = text

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

    def test_login_args_no_colon(self):
        (username, password) = self.registry.parse_login("username/password")
        self.assertEqual(username, None)
        self.assertEqual(password, None)
        self.assertEqual(self.registry.last_error, "Please provide -l in the form USER:PASSWORD")

class TestRegistrySend(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = TestRequests()
        self.registry.hostname = "http://testdomain.com"

    def test_get_ok(self):
        self.registry.http.reset_return_value(200)
        response = self.registry.send('/test_string')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.registry.last_error, None)
        self.registry.http.request.assert_called_with('GET',
                                                 'http://testdomain.com/test_string',
                                                 auth = (None, None),
                                                 headers = self.registry.HEADERS,
                                                 verify = True)

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
                                                 auth = ("test_login", "test_password"),
                                                 headers = self.registry.HEADERS,
                                                 verify = True)


class TestListImages(unittest.TestCase):

    def setUp(self):
        self.registry = Registry()
        self.registry.http = TestRequests()
        self.registry.hostname = "http://testdomain.com"

    def test_list_images_ok(self):
        self.registry.http.reset_return_value(status_code = 200,
                                              text = '{"repositories":["image1","image2"]}')
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
        self.registry.http = TestRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200)

    def test_list_one_tag_ok(self):
        self.registry.http.reset_return_value(status_code = 200,
            text = u'{"name":"image1","tags":["0.1.306"]}')

        response = self.registry.list_tags('image1')
        self.assertEqual(response, ["0.1.306"])
        self.assertEqual(self.registry.last_error, None)

    def test_list_tags_invalid_http_response(self):
        self.registry.http.reset_return_value(status_code = 400,
                                              text = "")

        response = self.registry.list_tags('image1')
        self.assertEqual(response, [])
        self.assertEqual(self.registry.last_error, 400)

    def test_list_tags_invalid_json(self):
        self.registry.http.reset_return_value(status_code=200,
                                              text="invalid_json")

        response = self.registry.list_tags('image1')
        self.assertEqual(response, [])
        self.assertEqual(self.registry.last_error, "list_tags: invalid json response")

    def test_list_tags_ok_sorted(self):
        def test_list_one_tag_ok(self):
            self.registry.http.reset_return_value(status_code=200,
                    text=u'{"name":"image1","tags":["0.1.306", "0.1.300", "0.1.290"]}')

            response = self.registry.list_tags('image1')
            self.assertEqual(response, ["0.1.290", "0.1.300", "0.1.306"])
            self.assertEqual(self.registry.last_error, None)


class TestListDigest(unittest.TestCase):
    def setUp(self):
        self.registry = Registry()
        self.registry.http = TestRequests()
        self.registry.hostname = "http://testdomain.com"
        self.registry.http.reset_return_value(200)

    def test_get_digest_ok(self):
        self.registry.http.reset_return_value(status_code = 200,
            text = ('{'
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
            auth = (None, None),
            headers = self.registry.HEADERS,
            verify = True
        )

        self.assertEqual(response, 'sha256:85295b0e7456a8fbbc886722b483f87f2bff553fa0beeaf37f5d807aff7c1e52')
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


class TestListLayers(unittest.TestCase):
    def setUp(self):
        self.registry = Registry()
        self.registry.http = TestRequests()
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
            auth = (None, None),
            headers = self.registry.HEADERS,
            verify = True
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
            auth = (None, None),
            headers = self.registry.HEADERS,
            verify = True
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


if __name__ == '__main__':
    unittest.main()