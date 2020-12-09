from synapse.http.server import (
    DirectServeHtmlResource,
    finish_request,
    respond_with_json
)


class SAML2LogoutResource(DirectServeHtmlResource):
    """
    A Twisted web resource which handles the SAML logout request
    and response
    """

    isLeaf = 1

    def __init__(self, hs):
        super().__init__()
        self._saml_handler = hs.get_saml_handler()

    async def _async_render_GET(self, request):
        if b"SAMLRequest" in request.args:
            logout_url = await self._saml_handler.handle_logout_request(request)
            request.redirect(logout_url)
            finish_request(request)
        elif b"SAMLResponse" in request.args:
            await self._saml_handler.handle_logout_response(request)
            respond_with_json(request, 200, {}, send_cors=True)
        else:
            request.setResponseCode(400)
            request.setHeader(b"Content-Type", b"text/plain")
            request.write(
                b"SAMLRequest or SAMLResponse should be "
                b"included in the query parameters."
            )
            finish_request(request)

    def render_OPTIONS(self, request):
        return respond_with_json(request, 200, {}, send_cors=True)
