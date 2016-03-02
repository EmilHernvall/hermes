Hermes DNS server
=================

Hermes is a compact DNS server in safe rust. It aims to provide a convenient
way of self-hosting a recursive resolver and local authority. It contains a
built-in administration web server which provides easy access to the resolver
cache and configuration of zones, either through a RESTish API or from the
browser through an HTML frontend.

API endpoints
-------------

 * /cache - GET
 * /authority - GET/POST
 * /authority/[zone] - GET/POST

