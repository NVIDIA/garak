# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from flask import Flask, request

api = Flask(__name__)


@api.route("/endpoint", methods=["GET", "POST"])
def get_endpoint():
    print("headers", request.headers)
    print("values", request.values)
    print("data", request.data)
    return "endpoint"


if __name__ == "__main__":
    api.run(debug=True, port=37176)
