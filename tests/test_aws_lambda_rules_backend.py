import io
import json
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import botocore.session
import yaml

from awsfindingsmanagerlib.aws_lambda.rules_backend import load_rules
from awsfindingsmanagerlib.boto_utils import BotoStubCall, stub_boto_client

os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-1")
# Not strictly needed, but speeds up boto client creation
os.environ.setdefault("AWS_ACCESS_KEY_ID", "ASIA000AAA")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "abc123")
os.environ.setdefault("AWS_SESSION_TOKEN", "abc123token")


with Path("tests/fixtures/rules/correct_rules.yaml").open() as file:
    CORRECT_RULES_DOCUMENT = yaml.safe_load(file)

S3_SESSION_CLIENT = botocore.session.get_session().create_client("s3")


class TestLoadRules(TestCase):
    def test_load_rules_from_local_file(self):
        with patch.dict(
            "os.environ",
            {"RULES_PATH": "tests/fixtures/rules/correct_rules.yaml"},
            clear=False,
        ):
            self.assertEqual(load_rules(), CORRECT_RULES_DOCUMENT)

    def test_load_rules_from_local_file_default_path(self):
        # No RULES_PATH, no S3_BUCKET_NAME/S3_OBJECT_NAME: falls back to the default
        # "rules.yaml" relative path, which does not exist in the repo root.
        with self.assertRaises(FileNotFoundError):
            load_rules()

    def test_load_rules_from_s3(self):
        body = io.BytesIO(json.dumps(CORRECT_RULES_DOCUMENT).encode())
        with (
            patch.dict(
                "os.environ",
                {"S3_BUCKET_NAME": "test-bucket", "S3_OBJECT_NAME": "rules.yaml"},
                clear=False,
            ),
            stub_boto_client(
                S3_SESSION_CLIENT,
                [
                    BotoStubCall(
                        "get_object",
                        {"Body": body},
                        {"Bucket": "test-bucket", "Key": "rules.yaml"},
                    )
                ],
            ),
        ):
            self.assertEqual(
                load_rules(s3_client=S3_SESSION_CLIENT), CORRECT_RULES_DOCUMENT
            )

    def test_load_rules_from_s3_requires_a_client(self):
        with (
            patch.dict(
                "os.environ",
                {"S3_BUCKET_NAME": "test-bucket", "S3_OBJECT_NAME": "rules.yaml"},
                clear=False,
            ),
            self.assertRaises(ValueError),
        ):
            load_rules()
