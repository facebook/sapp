# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
import os
from typing import Optional

import sqlalchemy

# pyre-fixme[21]: `flask` has no attribute `_app_ctx_stack`
from flask import Flask, send_from_directory, _app_ctx_stack
from flask.wrappers import Response
from flask_cors import CORS
from flask_graphql import GraphQLView
from pyre_extensions import none_throws
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from .. import models
from ..db import DB
from .filters import ServeExportFilter
from .schema import schema

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.DEBUG
)
LOG: logging.Logger = logging.getLogger(__name__)


application = Flask(
    __name__, static_folder=os.path.join(os.path.dirname(__file__), "frontend", "build")
)

session: Optional[Session] = None


@application.teardown_request
def shutdown_session(exception: Optional[Exception] = None) -> None:
    if session is not None:
        # pyre-fixme[16]: `Session` has no attribute `remove`.
        session.remove()


@application.route("/", defaults={"path": ""})
@application.route("/<path:path>")
def serve(path: str) -> Response:
    LOG.info(f"Serving `{path}`...")
    static_folder = none_throws(application.static_folder)
    if path != "" and os.path.exists(static_folder + "/" + path):
        LOG.info("Found static resource.")
        return send_from_directory(static_folder, path)
    else:
        LOG.info("Resource not found. Falling back to `index.html`")
        return send_from_directory(static_folder, "index.html")


def start_server(
    database: DB,
    debug: bool,
    static_resources: Optional[str],
    source_directory: str,
    editor_schema: Optional[str],
) -> None:
    engine = sqlalchemy.create_engine(
        sqlalchemy.engine.url.URL("sqlite", database=database.dbname),
        echo=False,
        poolclass=None,
    )
    session = scoped_session(
        sessionmaker(bind=engine),
        # pyre-fixme[16]: `flask` has no attribute _app_ctx_stack
        scopefunc=_app_ctx_stack.__ident_func__,
    )
    # pyre-fixme[16]: `Type` has no attribute `query`.
    models.Base.query = session.query_property()
    # We have additional tables for the UI that need to be created.
    models.create(database)

    application.add_url_rule(
        "/graphql",
        view_func=GraphQLView.as_view(
            "graphql",
            schema=schema,
            graphiql=True,
            get_context=lambda: {
                "session": session,
                "source_directory": os.path.expanduser(source_directory),
                "editor_schema": editor_schema,
            },
        ),
    )
    application.add_url_rule(
        "/export_filter/<string:filter_name>",
        view_func=ServeExportFilter.as_view("filter_export_view", session=session),
    )
    if static_resources:
        application.static_folder = static_resources
    if debug:
        CORS(application, resources={r"/graphql": {"origins": "http://localhost:3000"}})
    application.run(debug=debug, host="localhost", port=5000)
