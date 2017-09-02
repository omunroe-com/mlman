from mailman.config import config
from mailman.interfaces.plugin import IPlugin
from mailman.rest.helpers import bad_request, child, etag, no_content, okay
from mailman.rest.validator import Validator
from public import public
from zope.interface import implementer


@public
class Yes:
    def on_get(self, request, response):
        okay(response, etag(dict(yes=True)))


@public
class No:
    def on_get(self, request, response):
        bad_request(response, etag(dict(no=False)))


@public
class NumberEcho:
    def __init__(self):
        self._plugin = config.plugins['example']

    def on_get(self, request, response):
        okay(response, etag(dict(number=self._plugin.number)))

    def on_post(self, request, response):
        try:
            resource = Validator(number=int)(request)
            self._plugin.number = resource['number']
        except ValueError as error:
            bad_request(response, str(error))
        else:
            no_content(response)

    def on_delete(self, request, response):
        self._plugin.number = 0
        no_content(response)


@public
class RESTExample:
    def on_get(self, request, response):
        resource = {
            'my-name': 'example-plugin',
            'my-child-resources': 'yes, no, echo',
            }
        okay(response, etag(resource))

    @child()
    def yes(self, context, segments):
        return Yes(), []

    @child()
    def no(self, context, segments):
        return No(), []

    @child()
    def echo(self, context, segments):
        return NumberEcho(), []


@public
@implementer(IPlugin)
class ExamplePlugin:
    def __init__(self):
        self.number = 0

    def pre_hook(self):
        pass

    def post_hook(self):
        pass

    @property
    def resource(self):
        return RESTExample()
