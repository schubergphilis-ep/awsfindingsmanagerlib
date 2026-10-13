# AWS Lambda handlers

Requires the `lambda` extra (`awsfindingsmanagerlib[lambda]`). See "Running in AWS Lambda" on the home page
for the deployment contract (triggers, environment variables, IAM permissions).

## Handlers

::: awsfindingsmanagerlib.aws_lambda.scheduled.lambda_handler

::: awsfindingsmanagerlib.aws_lambda.events.lambda_handler

::: awsfindingsmanagerlib.aws_lambda.trigger.lambda_handler

::: awsfindingsmanagerlib.aws_lambda.worker.lambda_handler

## Rules loading

::: awsfindingsmanagerlib.aws_lambda.rules_backend.load_rules

See `awsfindingsmanagerlib.Manager.from_rules_document` (in "Main top-level functionality") for turning the
loaded document into a ready-to-use `Manager`.
