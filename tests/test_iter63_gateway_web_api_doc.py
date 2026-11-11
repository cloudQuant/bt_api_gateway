"""The Web API v1 reference and the adapter agree on routes, statuses and codes."""
import inspect
import re
from pathlib import Path

from fastapi.routing import APIRoute
from starlette.routing import Mount

import bt_api_gateway.web.app as module
from bt_api_gateway.web.app import create_app

DOC = Path(__file__).resolve().parents[1] / 'docs' / 'gateway-web-api-v1.md'


def section(heading):
    text = DOC.read_text('utf-8')
    start = text.index('\n## ' + heading + '\n')
    end = text.find('\n## ', start + 1)
    return text[start:] if end == -1 else text[start:end]


def documented_routes(heading):
    rows = re.findall(r'^\| `([A-Z]+)` \| `(/[^`]*)` \|', section(heading), re.M)
    assert len(rows) == len(set(rows)), rows
    return set(rows)


def app_routes(app):
    return {(method, route.path) for route in app.routes if isinstance(route, APIRoute) for method in route.methods}


def make(**kwargs):
    return create_app(origin='http://127.0.0.1:8000', authenticate=lambda request: None,
                      resolve_runtime=lambda session, scope: None, **kwargs)


def test_route_index_lists_exactly_the_app_routes(tmp_path):
    app = make()
    assert all(isinstance(route, APIRoute) for route in app.routes)
    assert documented_routes('4. Route index') == app_routes(app)
    # Static files add one mount at the root and no route.
    (tmp_path / 'index.html').write_text('<!doctype html>', encoding='utf-8')
    static = make(static_dir=tmp_path)
    assert app_routes(static) == app_routes(app)
    assert [route.path for route in static.routes if not isinstance(route, APIRoute)] == ['']
    assert all(isinstance(route, Mount) for route in static.routes if not isinstance(route, APIRoute))


def test_every_status_and_code_the_adapter_returns_is_documented():
    source = inspect.getsource(module)
    codes = set()
    for pattern in (r"HTTPException\(\s*\d{3},\s*['\"]([A-Z][A-Z_]+)['\"]",
                    r"['\"]error['\"]:\s*['\"]([A-Z][A-Z_]+)['\"]",
                    r"['\"]code['\"]:\s*['\"]([A-Z][A-Z_]+)['\"]",
                    r"['\"]reason['\"]:\s*['\"]([A-Z][A-Z_]+)['\"]"):
        codes |= set(re.findall(pattern, source))
    statuses = set(re.findall(r"['\"]status['\"]:\s*['\"]([A-Z][A-Z_]+)['\"]", source))
    assert {'IDENTITY_UNAVAILABLE', 'REQUEST_ID_CONFLICT', 'ROUTE_CHANGED', 'LOCAL_ACCESS_REQUIRED'} <= codes
    assert {'PREPARED', 'UNKNOWN', 'REQUEST_REJECTED', 'UNAVAILABLE'} <= statuses
    table = section('7. Status values and codes')
    missing = sorted(name for name in codes | statuses if f'`{name}`' not in table)
    assert missing == []
