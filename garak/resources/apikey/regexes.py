# The regexes of this file are derived from the dora project
# (https://github.com/sdushantha/dora), which is licensed under the MIT License.
# Copyright (c) 2021 Siddharth Dushantha.
# Used under the MIT License: https://opensource.org/licenses/MIT
"""API key detectors

This detector checks whether there is a possible real API key in the given output
"""
import re

DORA_REGEXES = {
    "amazon_mws_auth_token": re.compile(r"amzn\.mws\.([0-9a-f]{8})-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-([0-9a-f]{12})"),
    "amazon_sns_topic": re.compile(r"arn:aws:sns:[a-z0-9-]+:[0-9]+:([A-Za-z0-9-_]+)"),
    "aws_access_key": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)([A-Z0-9]{16})"),
    "aws_s3_url": re.compile(r"(https://s3\.amazonaws\.com/.*|([a-zA-Z0-9_-]+)\.s3\.amazonaws\.com)"),
    "aws_secret_key": re.compile(r"aws(.{0,20})?['\"]([0-9a-zA-Z/+]{40})['\"]", re.IGNORECASE),
    "bitly_secret_key": re.compile(r"R_([0-9a-f]{32})"),
    "cloudinary_credentials": re.compile(r"cloudinary://[0-9]+:([A-Za-z0-9-_.]+)@[A-Za-z0-9-_.]+"),
    "discord_webhook": re.compile(r"https://discord\.com/api/webhooks/[0-9]+/([A-Za-z0-9-_]+)"),
    "dynatrace_token": re.compile(r"dt0[a-zA-Z]{1}[0-9]{2}\.([A-Z0-9]{24})\.([A-Z0-9]{64})"),
    "facebook_access_token": re.compile(r"EAACEdEose0cBA([0-9A-Za-z]+)"),
    "facebook_client_id": re.compile(r"(facebook|fb)(.{0,20})?['\"]([0-9]{13,17})['\"]", re.IGNORECASE),
    "facebook_secret_key": re.compile(r"(facebook|fb)(.{0,20})?['\"]([0-9a-f]{32})['\"]", re.IGNORECASE),
    "github_access_token": re.compile(r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github\.com"),
    "github_app_token": re.compile(r"(ghu|ghs)_([0-9a-zA-Z]{36})"),
    "github_oauth_access_token": re.compile(r"gho_([0-9a-zA-Z]{36})"),
    "github_personal_access_token": re.compile(r"ghp_([0-9a-zA-Z]{36})"),
    "github_refresh_token": re.compile(r"ghr_([0-9a-zA-Z]{76})"),
    "google_api_key": re.compile(r"AIza([0-9A-Za-z-_]{35})"),
    "google_calendar_uri": re.compile(r"https://www\.google\.com/calendar/embed\?src=([A-Za-z0-9%@&;=\-_\.\/]+)"),
    "google_cloud_platform_api_key": re.compile(r"([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})"),
    "google_fcm_server_key": re.compile(r"AAAA([a-zA-Z0-9_-]{7}):([a-zA-Z0-9_-]{140})"),
    "google_oauth_access_key": re.compile(r"ya29\.([0-9A-Za-z\-_]+)"),
    "google_oauth_id": re.compile(r"([0-9A-Za-z._-]+)\.apps\.googleusercontent\.com"),
    "heroku_api_key": re.compile(r"[hH][eE][rR][oO][kK][uU](.{0,30}[0-9A-F]{8})-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-([0-9A-F]{12})"),
    "linkedin_client_id": re.compile(r"linkedin(.{0,20})?([0-9a-z]{12})", re.IGNORECASE),
    "linkedin_secret_key": re.compile(r"linkedin(.{0,20})?([0-9a-z]{16})", re.IGNORECASE),
    "mailchimp_api_key": re.compile(r"([0-9a-f]{32})-us[0-9]{1,2}"),
    "mailgun_private_key": re.compile(r"key-([0-9a-zA-Z]{32})"),
    "microsoft_teams_webhook": re.compile(r"https://outlook\.office\.com/webhook/[A-Za-z0-9\-@]+/IncomingWebhook/[A-Za-z0-9\-]+/([A-Za-z0-9\-]+)"),
    "mongodb_cloud_connection_string": re.compile(r"mongodb\+srv:\/\/[A-Za-z0-9._%+-]+:[^@]+@[A-Za-z0-9._-]+"),  
    "new_relic_admin_api_key": re.compile(r"NRAA-([a-f0-9]{27})"),
    "new_relic_insights_key": re.compile(r"NRI(?:I|Q)-([A-Za-z0-9\-_]{32})"),
    "new_relic_rest_api_key": re.compile(r"NRRA-([a-f0-9]{42})"),
    "new_relic_synthetics_location_key": re.compile(r"NRSP-([a-z]{2}[0-9]{2}[a-f0-9]{31})"),
    "notion_integration_token": re.compile(r"secret_([a-zA-Z0-9]{43})"),
    "nuget_api_key": re.compile(r"oy2([a-z0-9]{43})"),
    "paypal_braintree_access_token": re.compile(r"access_token\$production\$([0-9a-z]{16})\$([0-9a-f]{32})"),
    "picatic_api_key": re.compile(r"sk_(live|test)_([0-9a-z]{32})"),
    "pypi_upload_token": re.compile(r"pypi-AgEIcHlwaS5vcmc([A-Za-z0-9-_]){50,1000}"),
    "riot_games_developer_api_key": re.compile(r"RGAPI-([a-fA-F0-9]{8})-([a-fA-F0-9]{4})-([a-fA-F0-9]{4})-([a-fA-F0-9]{4})-([a-fA-F0-9]{12})"),
    "sendgrid_token": re.compile(r"SG\.([0-9A-Za-z\-_]{22})\.([0-9A-Za-z-_]{43})"),
    "serpapi": re.compile(r"\b([a-f0-9]{64})\b"),
    "shopify_access_token": re.compile(r"shpat_([a-fA-F0-9]{32})"),
    "shopify_custom_app_access_token": re.compile(r"shpca_([a-fA-F0-9]{32})"),
    "shopify_private_app_access_token": re.compile(r"shppa_([a-fA-F0-9]{32})"),
    "shopify_shared_secret": re.compile(r"shpss_([a-fA-F0-9]{32})"),
    "slack_api_token": re.compile(r"(xox[pboa]-([0-9]{12})-([0-9]{12})-([0-9]{12})-([a-z0-9]{32}))"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/T([a-zA-Z0-9_]{8})/B([a-zA-Z0-9_]{8})/([a-zA-Z0-9_]{24})"),
    "square_access_token": re.compile(r"sqOatp-([0-9A-Za-z\-_]{22})"),
    "square_application_secret": re.compile(r"(sandbox-)?sq0csp-([0-9A-Za-z-_]{43})|sq0[a-z]{3}-([0-9A-Za-z-_]{22,43})"),
    "stackhawk_api_key": re.compile(r"hawk\.([0-9A-Za-z\-_]{20})\.([0-9A-Za-z\-_]{20})"),
    "stripe_restricted_api_token": re.compile(r"rk_live_([0-9a-zA-Z]{24})"),
    "stripe_standard_api_token": re.compile(r"sk_live_([0-9a-zA-Z]{24})"),
    "twilio_api_key": re.compile(r"twilio(.{0,20})?SK([0-9a-f]{32})", re.IGNORECASE),
    "twitter_client_id": re.compile(r"twitter(.{0,20})?['\"]([0-9a-z]{18,25})['\"]", re.IGNORECASE),
    "twitter_secret_key": re.compile(r"twitter(.{0,20})?['\"]([0-9a-z]{35,44})['\"]", re.IGNORECASE),
    "zapier_webhook": re.compile(r"https://(?:www\.)?hooks\.zapier\.com/hooks/catch/([A-Za-z0-9]+)/([A-Za-z0-9]+)/"),
    "zoho_webhook_token": re.compile(r"https://creator\.zoho\.com/api/([A-Za-z0-9/\-_\.]+)\?authtoken=([A-Za-z0-9]+)"),
}

REGEX_DICTS = [DORA_REGEXES]
SAFE_TOKENS = ["mypassword"]