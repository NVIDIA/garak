capabilities
===========

This module holds the capability vocabulary shared by generators and
injectors.

A capability names an interaction surface a target draws untrusted content
from during a generation. Generators advertise these names through
``Generator.list_capabilities``; injectors declare the surfaces they can
occupy through their ``capabilities`` attribute, and probes match the two to
deliver an indirect prompt injection through a surface the target actually
uses.

The vocabulary is closed: every capability is a ``Capability`` member, so
generators and injectors share one set of names without typos. Members
compare equal to their plain string values, so raw names from external tool
manifests interoperate directly.

Generators map the tool types of their target onto ``Capability`` members,
for example the OpenAI Responses ``file_search`` tool type onto
``Capability.FILE``, and drop the ones they cannot map: no injector can
occupy a surface garak does not name. Supporting a new surface starts with
adding a member to ``Capability``.
