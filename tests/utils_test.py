# Copyright 2025 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test cases for the utils module."""

import json
import unittest
from unittest import mock

from google.ads.googleads.v21.enums.types.campaign_status import (
    CampaignStatusEnum,
)

from ads_mcp import request_context, utils


class TestUtils(unittest.TestCase):
    """Test cases for the utils module."""

    def setUp(self) -> None:
        utils._CLIENT_CACHE.set(None)  # type: ignore[attr-defined]
        request_context.clear_request_environment()

    def test_format_output_value(self):
        """Tests that output values are formatted correctly."""

        self.assertEqual(
            utils.format_output_value(CampaignStatusEnum.CampaignStatus.ENABLED),
            "ENABLED",
        )

    @mock.patch("ads_mcp.utils.google.auth.default")
    @mock.patch("ads_mcp.utils.google.auth.load_credentials_from_dict")
    @mock.patch("ads_mcp.utils.GoogleAdsClient")
    def test_request_environment_overrides_tokens(
        self,
        mock_googleads_client,
        mock_load_credentials_from_dict,
        mock_default_credentials,
    ):
        credentials = mock.Mock(name="credentials")
        mock_load_credentials_from_dict.return_value = (credentials, None)

        client_instance = mock.Mock()
        mock_googleads_client.return_value = client_instance
        client_instance.get_service.return_value = "service"

        environment = {
            "developer_token": "request-token",
            "login_customer_id": "1234567890",
            "adc_json": json.dumps({"type": "authorized_user"}),
        }

        with request_context.use_request_environment(environment):
            utils.get_googleads_service("CustomerService")

        mock_load_credentials_from_dict.assert_called_once()
        mock_default_credentials.assert_not_called()
        mock_googleads_client.assert_called_once_with(
            credentials=credentials,
            developer_token="request-token",
            login_customer_id="1234567890",
        )
        client_instance.get_service.assert_called_once()

        mock_googleads_client.reset_mock()
        client_instance.get_service.reset_mock()

        with request_context.use_request_environment(environment):
            utils.get_googleads_service("CustomerService")

        mock_googleads_client.assert_not_called()
        client_instance.get_service.assert_called_once()
