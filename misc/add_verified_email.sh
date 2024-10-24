#!/bin/sh

AWS_DEFAULT_REGION=us-west-2 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test awslocal ses verify-email-identity --email noreply@brave.com
